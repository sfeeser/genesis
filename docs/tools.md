### MCP-like tool-Use

- **Human-like reasoning**: Real senior engineers don’t get every possible piece of context dumped on them at once. They ask questions when they need them ("What does this other node look like?", "Show me the original spec paragraph again", "What happened the last two times we tried this?").
- **Efficiency**: Most decisions don’t need the full history of every node. Tool-use lets me stay lightweight until I actually need more context.
- **Better judgement**: When I hit a regression or a tricky mutation decision, I can actively pull exactly what I need (project health, related nodes, previous LLM reasoning, full SpecBook paragraph, etc.) instead of hoping it was included.
- **Reduced hallucination / overconfidence**: If I can ask, I’m less likely to guess or make assumptions.
- **Future-proof**: This scales much better as the codebase grows.

Conditional pushing (only send extra data when there’s a regression) is a reasonable fallback, but it still forces the system designer to guess what I’ll need. Tool-use lets *me* decide.

### What Tools I Would Want as the Synthesis AI

If we give me tool access, here’s what I would actually use in practice:

1. `get_node_history(node_id)` — full growth_history + white_blood_cell_attacks + synthesis_outcome_history
2. `get_original_spec(node_id)` — the exact SpecBook text this node was born from
3. `get_related_nodes(node_id, limit)` — summary of neighboring nodes by coreness or dependency
4. `get_project_health()` — current overall project consistency score
5. `get_previous_llm_reasoning(node_id)` — what I said the last time I worked on this node
6. `get_blast_radius(node_id)` — fresh blast radius on demand
7. `get_node_code(node_id)` — current implementation (if any)

With these, I would feel **extremely close to human-level judgement** (easily 9/10 or better).
