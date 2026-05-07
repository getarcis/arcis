//! Dependency-graph primitives for `arcis sca` transitive-depth tracking
//! (cli-sca.md Phase C item 5).
//!
//! The graph is built once per lockfile by the format-specific parsers in
//! [`crate::sca_lockfile`], then walked by [`crate::sca::scan_project_with_paths`]
//! to annotate each `Finding` with its shortest root → parent chain.
//!
//! # Path semantics
//!
//! For a target node `T`:
//! * **depth** is the number of edges on the shortest root → T path.
//!   `depth == 1` means a direct dependency; `depth == 3` means three hops
//!   away from any root.
//! * **path** is the chain of *names* visited en route, **not** including T
//!   itself — the renderer pairs the path with `T@version` separately. So
//!   for `your-app → middleware → axios`, calling `shortest_path(axios)`
//!   returns `["your-app", "middleware"]` and depth is 2.
//! * Nodes are keyed on `(ecosystem, name, version)` so two installations
//!   of the same package at different versions are distinct nodes — npm
//!   hoisting routinely produces this case.
//!
//! # Cycle handling
//!
//! BFS naturally handles cycles via the visited-set; nothing in the graph
//! API recurses, so a self-referential dependency or a longer cycle just
//! truncates at the BFS frontier.

use std::collections::{HashMap, VecDeque};

/// Index into [`DepGraph::nodes`]. Cheap to copy and `Eq`/`Hash`-able for
/// use in visited sets.
pub type NodeId = usize;

/// One node in the dependency graph. Identity is the
/// `(ecosystem, name, version)` triple stored in [`DepGraph::index`];
/// the node itself only carries `name` because that's all the path
/// renderer needs. Re-introduce ecosystem + version here when a future
/// caller needs versioned-name display ("axios@1.14.1 → ...").
#[derive(Debug, Clone)]
struct Node {
    name: String,
}

/// Directed dependency graph rooted at one or more project entry points.
/// Edges go from a package to its direct dependencies; roots are the
/// pseudo-nodes representing the project's manifest declarations.
///
/// Construction is incremental: builders call [`Self::add_node`] /
/// [`Self::add_edge`] / [`Self::add_root`] in any order; duplicate
/// `(ecosystem, name, version)` triples coalesce to one [`NodeId`].
#[derive(Debug, Default, Clone)]
pub struct DepGraph {
    nodes: Vec<Node>,
    /// `edges[i]` lists the children of node `i`.
    edges: Vec<Vec<NodeId>>,
    roots: Vec<NodeId>,
    /// `(ecosystem, name, version)` → NodeId. Built lazily by `add_node`.
    index: HashMap<(String, String, String), NodeId>,
}

impl DepGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a node, returning its existing id if already present. Uses
    /// `(ecosystem, name, version)` as the identity key — see module docs.
    pub fn add_node(&mut self, ecosystem: &str, name: &str, version: &str) -> NodeId {
        let key = (ecosystem.to_string(), name.to_string(), version.to_string());
        if let Some(&id) = self.index.get(&key) {
            return id;
        }
        let id = self.nodes.len();
        self.nodes.push(Node {
            name: name.to_string(),
        });
        self.edges.push(Vec::new());
        self.index.insert(key, id);
        id
    }

    /// Lookup without inserting. Returns `None` if the triple is unknown.
    pub fn find_node(&self, ecosystem: &str, name: &str, version: &str) -> Option<NodeId> {
        self.index
            .get(&(ecosystem.to_string(), name.to_string(), version.to_string()))
            .copied()
    }

    /// Add a directed edge `from → to`. Idempotent: re-adding the same
    /// edge is a no-op so callers don't have to track what they've inserted.
    pub fn add_edge(&mut self, from: NodeId, to: NodeId) {
        if from >= self.edges.len() || to >= self.nodes.len() {
            return;
        }
        if !self.edges[from].contains(&to) {
            self.edges[from].push(to);
        }
    }

    /// Mark `id` as one of the project's roots. Multiple roots are allowed
    /// (workspaces, monorepo importers); BFS sources from all of them.
    pub fn add_root(&mut self, id: NodeId) {
        if id < self.nodes.len() && !self.roots.contains(&id) {
            self.roots.push(id);
        }
    }

    /// Number of nodes currently in the graph.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of root nodes registered.
    pub fn root_count(&self) -> usize {
        self.roots.len()
    }

    /// Run a multi-source BFS from `self.roots`, returning per-node
    /// distance and the minimum-distance predecessor list (used by
    /// [`Self::shortest_path`] and [`Self::all_paths_to`]).
    fn bfs(&self) -> (Vec<Option<usize>>, Vec<Vec<NodeId>>) {
        let n = self.nodes.len();
        let mut dist: Vec<Option<usize>> = vec![None; n];
        let mut preds: Vec<Vec<NodeId>> = vec![Vec::new(); n];
        let mut queue: VecDeque<NodeId> = VecDeque::new();

        for &r in &self.roots {
            if dist[r].is_none() {
                dist[r] = Some(0);
                queue.push_back(r);
            }
        }

        while let Some(u) = queue.pop_front() {
            let du = dist[u].unwrap_or(usize::MAX);
            for &v in &self.edges[u] {
                match dist[v] {
                    None => {
                        dist[v] = Some(du + 1);
                        preds[v].push(u);
                        queue.push_back(v);
                    }
                    // Equal-distance alternate predecessor: record so
                    // `all_paths_to` can enumerate every shortest path.
                    Some(dv) if dv == du + 1 && !preds[v].contains(&u) => {
                        preds[v].push(u);
                    }
                    _ => {}
                }
            }
        }

        (dist, preds)
    }

    /// Shortest depth (edge count) from any root to `target`. `Some(0)`
    /// means the target is itself a root; `None` means unreachable.
    pub fn depth(&self, target: NodeId) -> Option<usize> {
        let (dist, _) = self.bfs();
        dist.get(target).copied().flatten()
    }

    /// Return one shortest root → target chain as a list of package
    /// **names**, **excluding** the target itself.
    ///
    /// Tie-break: when multiple shortest paths exist, the predecessor with
    /// the lexicographically smallest name wins at every step — gives a
    /// stable, reproducible single-path render across runs.
    ///
    /// `None` if the target is unreachable from any root.
    pub fn shortest_path(&self, target: NodeId) -> Option<Vec<String>> {
        let (dist, preds) = self.bfs();
        if target >= self.nodes.len() || dist[target].is_none() {
            return None;
        }

        let mut chain: Vec<NodeId> = Vec::new();
        let mut cur = target;
        while !self.roots.contains(&cur) {
            let parents = &preds[cur];
            if parents.is_empty() {
                return None;
            }
            let &p = parents
                .iter()
                .min_by(|&&a, &&b| self.nodes[a].name.cmp(&self.nodes[b].name))
                .unwrap();
            chain.push(p);
            cur = p;
        }
        chain.reverse();
        // `chain` is now `[root, hop1, ..., parent_of_target]`. We exclude
        // the target name itself per module docs.
        Some(
            chain
                .into_iter()
                .map(|id| self.nodes[id].name.clone())
                .collect(),
        )
    }

    /// Enumerate every shortest root → target chain, capped at `cap`
    /// entries to bound output size on diamond-heavy graphs.
    ///
    /// Without the cap, a graph where the target is reachable through K
    /// independent equal-length subgraphs produces 2^K paths (combinatorial
    /// blowup). The default 8-path cap in `crate::sca` is empirical:
    /// covers realistic monorepo diamond cases without ever flooding the
    /// CLI's `--verbose` render.
    ///
    /// Each returned `Vec<String>` follows the same convention as
    /// [`Self::shortest_path`]: list of package names, target excluded.
    /// If `target` is itself a root, the returned vector contains one
    /// empty path (depth 0).
    pub fn all_paths_to(&self, target: NodeId, cap: usize) -> Vec<Vec<String>> {
        let (dist, preds) = self.bfs();
        if target >= self.nodes.len() || dist[target].is_none() {
            return Vec::new();
        }
        if cap == 0 {
            return Vec::new();
        }
        if self.roots.contains(&target) {
            return vec![Vec::new()];
        }

        let mut out: Vec<Vec<NodeId>> = Vec::new();
        let mut stack: Vec<NodeId> = Vec::new();
        self.walk_paths(target, target, &preds, &mut stack, &mut out, cap);

        // `out` chains already read [root, hop1, ..., parent_of_target].
        let mut paths: Vec<Vec<String>> = out
            .into_iter()
            .map(|chain| {
                chain
                    .into_iter()
                    .map(|id| self.nodes[id].name.clone())
                    .collect::<Vec<_>>()
            })
            .collect();
        paths.sort();
        paths.dedup();
        paths.truncate(cap);
        paths
    }

    /// Recursive helper for [`Self::all_paths_to`]. The `stack` invariant
    /// is: stack holds the chain from the *target's parent* back to (but
    /// excluding) `cur`, in target → root order. When `cur` reaches a
    /// root, the final chain is `[root] + stack.iter().rev()` —
    /// reading root → parent_of_target.
    ///
    /// Target itself is excluded from the chain, so the entry call at
    /// `cur == target` skips the stack push.
    fn walk_paths(
        &self,
        cur: NodeId,
        target: NodeId,
        preds: &[Vec<NodeId>],
        stack: &mut Vec<NodeId>,
        out: &mut Vec<Vec<NodeId>>,
        cap: usize,
    ) {
        if out.len() >= cap {
            return;
        }
        if self.roots.contains(&cur) {
            let mut chain: Vec<NodeId> = Vec::with_capacity(stack.len() + 1);
            chain.push(cur);
            chain.extend(stack.iter().rev().copied());
            out.push(chain);
            return;
        }
        let mut parents = preds[cur].clone();
        parents.sort_by(|&a, &b| self.nodes[a].name.cmp(&self.nodes[b].name));
        for p in parents {
            let pushed = if cur != target {
                stack.push(cur);
                true
            } else {
                false
            };
            self.walk_paths(p, target, preds, stack, out, cap);
            if pushed {
                stack.pop();
            }
            if out.len() >= cap {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph_with_nodes(triples: &[(&str, &str, &str)]) -> (DepGraph, Vec<NodeId>) {
        let mut g = DepGraph::new();
        let ids: Vec<NodeId> = triples
            .iter()
            .map(|(e, n, v)| g.add_node(e, n, v))
            .collect();
        (g, ids)
    }

    #[test]
    fn add_node_dedupes_on_eco_name_version() {
        let mut g = DepGraph::new();
        let a = g.add_node("npm", "axios", "1.14.1");
        let b = g.add_node("npm", "axios", "1.14.1");
        assert_eq!(a, b);
        assert_eq!(g.node_count(), 1);
    }

    #[test]
    fn add_node_distinguishes_versions() {
        let mut g = DepGraph::new();
        let a = g.add_node("npm", "axios", "1.14.1");
        let b = g.add_node("npm", "axios", "1.7.0");
        assert_ne!(a, b);
        assert_eq!(g.node_count(), 2);
    }

    #[test]
    fn add_edge_idempotent() {
        let (mut g, ids) = graph_with_nodes(&[("npm", "a", "1"), ("npm", "b", "1")]);
        g.add_edge(ids[0], ids[1]);
        g.add_edge(ids[0], ids[1]);
        assert_eq!(g.edges[ids[0]].len(), 1);
    }

    #[test]
    fn shortest_path_direct_dep() {
        let (mut g, ids) =
            graph_with_nodes(&[("npm", "your-app", "1.0.0"), ("npm", "axios", "1.14.1")]);
        g.add_root(ids[0]);
        g.add_edge(ids[0], ids[1]);
        let p = g.shortest_path(ids[1]).unwrap();
        assert_eq!(p, vec!["your-app".to_string()]);
        assert_eq!(g.depth(ids[1]), Some(1));
    }

    #[test]
    fn shortest_path_three_hops() {
        let (mut g, ids) = graph_with_nodes(&[
            ("npm", "your-app", "1"),
            ("npm", "express", "4"),
            ("npm", "middleware", "1"),
            ("npm", "axios", "1.14.1"),
        ]);
        g.add_root(ids[0]);
        g.add_edge(ids[0], ids[1]);
        g.add_edge(ids[1], ids[2]);
        g.add_edge(ids[2], ids[3]);
        let p = g.shortest_path(ids[3]).unwrap();
        assert_eq!(p, vec!["your-app", "express", "middleware"]);
        assert_eq!(g.depth(ids[3]), Some(3));
    }

    #[test]
    fn shortest_path_picks_shortest_when_two_paths() {
        // root → A → axios (depth 2)
        // root → B → C → axios (depth 3)
        // shortest_path picks the depth-2 chain.
        let (mut g, ids) = graph_with_nodes(&[
            ("npm", "root", "1"),
            ("npm", "a", "1"),
            ("npm", "b", "1"),
            ("npm", "c", "1"),
            ("npm", "axios", "1.14.1"),
        ]);
        g.add_root(ids[0]);
        g.add_edge(ids[0], ids[1]);
        g.add_edge(ids[0], ids[2]);
        g.add_edge(ids[1], ids[4]);
        g.add_edge(ids[2], ids[3]);
        g.add_edge(ids[3], ids[4]);
        let p = g.shortest_path(ids[4]).unwrap();
        assert_eq!(p, vec!["root", "a"]);
        assert_eq!(g.depth(ids[4]), Some(2));
    }

    #[test]
    fn shortest_path_lex_tiebreak_among_equal_length() {
        // root → bravo → axios
        // root → alpha → axios
        // same depth (2); lex tiebreak picks "alpha".
        let (mut g, ids) = graph_with_nodes(&[
            ("npm", "root", "1"),
            ("npm", "alpha", "1"),
            ("npm", "bravo", "1"),
            ("npm", "axios", "1"),
        ]);
        g.add_root(ids[0]);
        g.add_edge(ids[0], ids[1]);
        g.add_edge(ids[0], ids[2]);
        g.add_edge(ids[1], ids[3]);
        g.add_edge(ids[2], ids[3]);
        let p = g.shortest_path(ids[3]).unwrap();
        assert_eq!(p, vec!["root", "alpha"]);
    }

    #[test]
    fn all_paths_to_enumerates_diamond() {
        let (mut g, ids) = graph_with_nodes(&[
            ("npm", "root", "1"),
            ("npm", "alpha", "1"),
            ("npm", "bravo", "1"),
            ("npm", "axios", "1"),
        ]);
        g.add_root(ids[0]);
        g.add_edge(ids[0], ids[1]);
        g.add_edge(ids[0], ids[2]);
        g.add_edge(ids[1], ids[3]);
        g.add_edge(ids[2], ids[3]);
        let paths = g.all_paths_to(ids[3], 8);
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&vec!["root".to_string(), "alpha".to_string()]));
        assert!(paths.contains(&vec!["root".to_string(), "bravo".to_string()]));
    }

    #[test]
    fn all_paths_to_excludes_longer_routes() {
        // root → a → axios   (depth 2 — kept)
        // root → b → c → axios (depth 3 — excluded by BFS shortest-path semantics)
        let (mut g, ids) = graph_with_nodes(&[
            ("npm", "root", "1"),
            ("npm", "a", "1"),
            ("npm", "b", "1"),
            ("npm", "c", "1"),
            ("npm", "axios", "1"),
        ]);
        g.add_root(ids[0]);
        g.add_edge(ids[0], ids[1]);
        g.add_edge(ids[0], ids[2]);
        g.add_edge(ids[1], ids[4]);
        g.add_edge(ids[2], ids[3]);
        g.add_edge(ids[3], ids[4]);
        let paths = g.all_paths_to(ids[4], 8);
        assert_eq!(paths, vec![vec!["root".to_string(), "a".to_string()]]);
    }

    #[test]
    fn all_paths_to_respects_cap() {
        // 4 disjoint depth-2 chains; cap=2 should truncate.
        let (mut g, ids) = graph_with_nodes(&[
            ("npm", "root", "1"),
            ("npm", "a", "1"),
            ("npm", "b", "1"),
            ("npm", "c", "1"),
            ("npm", "d", "1"),
            ("npm", "target", "1"),
        ]);
        g.add_root(ids[0]);
        for i in 1..=4 {
            g.add_edge(ids[0], ids[i]);
            g.add_edge(ids[i], ids[5]);
        }
        let paths = g.all_paths_to(ids[5], 2);
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn cycle_does_not_loop_forever() {
        // root → a → b → a (cycle); axios under b.
        let (mut g, ids) = graph_with_nodes(&[
            ("npm", "root", "1"),
            ("npm", "a", "1"),
            ("npm", "b", "1"),
            ("npm", "axios", "1"),
        ]);
        g.add_root(ids[0]);
        g.add_edge(ids[0], ids[1]);
        g.add_edge(ids[1], ids[2]);
        g.add_edge(ids[2], ids[1]); // cycle
        g.add_edge(ids[2], ids[3]);
        let p = g.shortest_path(ids[3]).unwrap();
        assert_eq!(p, vec!["root", "a", "b"]);
        assert_eq!(g.depth(ids[3]), Some(3));
    }

    #[test]
    fn unreachable_target_returns_none() {
        let (mut g, ids) = graph_with_nodes(&[("npm", "root", "1"), ("npm", "orphan", "1")]);
        g.add_root(ids[0]);
        // No edge to orphan.
        assert!(g.shortest_path(ids[1]).is_none());
        assert_eq!(g.depth(ids[1]), None);
    }

    #[test]
    fn multiple_roots_pick_nearest() {
        // root_a → axios (depth 1)
        // root_b → mid → axios (depth 2)
        let (mut g, ids) = graph_with_nodes(&[
            ("npm", "root_a", "1"),
            ("npm", "root_b", "1"),
            ("npm", "mid", "1"),
            ("npm", "axios", "1"),
        ]);
        g.add_root(ids[0]);
        g.add_root(ids[1]);
        g.add_edge(ids[0], ids[3]);
        g.add_edge(ids[1], ids[2]);
        g.add_edge(ids[2], ids[3]);
        let p = g.shortest_path(ids[3]).unwrap();
        assert_eq!(p, vec!["root_a"]);
        assert_eq!(g.depth(ids[3]), Some(1));
    }

    #[test]
    fn root_target_returns_empty_path() {
        let (mut g, ids) = graph_with_nodes(&[("npm", "root", "1")]);
        g.add_root(ids[0]);
        // target IS the root → empty parent chain, depth 0
        let p = g.shortest_path(ids[0]).unwrap();
        assert!(p.is_empty());
        assert_eq!(g.depth(ids[0]), Some(0));
    }

    #[test]
    fn find_node_returns_existing_id() {
        let mut g = DepGraph::new();
        let id = g.add_node("npm", "axios", "1.14.1");
        assert_eq!(g.find_node("npm", "axios", "1.14.1"), Some(id));
        assert_eq!(g.find_node("npm", "axios", "9.9.9"), None);
    }
}
