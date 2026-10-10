---
description: Configure, implement, debug, and validate LangGraph
  applications in Python. Use when setting up LangGraph projects,
  defining graph state and nodes, adding routing, persistence, memory,
  streaming, human-in-the-loop workflows, or preparing a graph for
  deployment.
name: configure-langgraph
---

# Configure LangGraph

## Purpose

Help the developer configure a reliable LangGraph application that is
easy to understand, test, and maintain. Prefer the smallest architecture
that meets the requirements. Use current official LangGraph
documentation when APIs or package names may have changed.

## 1. First inspect the project

Before changing files:

1.  Inspect the repository structure, Python version, dependency
    manager, existing entry points, and current LangChain/LangGraph
    versions.
2.  Read `pyproject.toml`, `requirements.txt`, `.env.example`, README,
    and relevant source files when present.
3.  Identify whether the project uses plain LangGraph, LangChain model
    integrations, LangGraph CLI/Agent Server, or a hosted deployment.
4.  Preserve existing conventions and avoid replacing working
    architecture without a clear reason.
5.  Ask a concise question only when an essential requirement is
    missing; otherwise use sensible defaults and state them.

Do not assume an API from an old tutorial is still current. Check the
installed package version and official documentation before making
version-sensitive changes.

## 2. Installation and environment

Use the project's existing package manager. If starting a new Python
project, prefer a virtual environment and a reproducible dependency
file.

Typical core installation:

``` bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate

python -m pip install -U langgraph
```

Install only integrations the project actually needs. For example,
install the relevant model-provider integration (such as
`langchain-openai`) or database checkpointer package separately when
required. Do not install every optional integration pre-emptively.

Keep secrets in environment variables or a secret manager. Provide
`.env.example` with placeholder names, never real credentials. Do not
commit `.env`, API keys, access tokens, or database passwords.

Example `.env.example`:

``` dotenv
MODEL_PROVIDER_API_KEY=replace-me
DATABASE_URL=replace-me
LANGSMITH_TRACING=false
LANGSMITH_API_KEY=replace-me
```

Use the exact environment variable expected by the chosen provider; do
not assume all providers use the same key name.

## 3. Define the graph contract before implementation

Write down:

-   The graph's input and expected output.
-   State fields, types, and ownership.
-   Nodes and what each node is responsible for.
-   Edges and conditional routing rules.
-   Failure, retry, timeout, and termination behavior.
-   Whether conversation state must survive between invocations.
-   Whether users must approve consequential actions.
-   Observability, privacy, and testing requirements.

Keep nodes focused and deterministic where possible. Put model calls and
external side effects behind clear functions so they can be tested
independently.

## 4. Build a minimal graph

Use `StateGraph` with an explicit state schema. `TypedDict` is suitable
for straightforward state; use a validation-oriented schema when runtime
validation is important.

Minimal example:

``` python
from typing import TypedDict
from langgraph.graph import StateGraph, START, END

class State(TypedDict):
    message: str
    result: str

def process(state: State) -> dict:
    return {"result": state["message"].strip().upper()}

builder = StateGraph(State)
builder.add_node("process", process)
builder.add_edge(START, "process")
builder.add_edge("process", END)

graph = builder.compile()

result = graph.invoke({
    "message": "hello langgraph",
    "result": "",
})
print(result["result"])
```

Implementation rules:

-   Nodes receive the current state and return a partial state update,
    not an unrelated object.
-   Do not mutate shared state in place unless the selected API
    explicitly requires it.
-   Keep state serializable for checkpointing.
-   Use reducers for fields that need to accumulate or merge values,
    such as message histories.
-   Avoid storing API clients, open file handles, database connections,
    or other non-serializable runtime objects in graph state.
-   Use stable, descriptive node names.
-   Ensure every normal execution path reaches a valid next node or
    `END`.

## 5. Add conditional routing deliberately

Use conditional edges when the next node depends on state or a decision.
Keep routing functions small and return only documented route names.

``` python
from typing import Literal
from langgraph.graph import StateGraph, START, END

def route(state) -> Literal["continue", "finish"]:
    return "finish" if state["done"] else "continue"

builder.add_conditional_edges(
    "check",
    route,
    {
        "continue": "work",
        "finish": END,
    },
)
```

Check for:

-   Missing route-map keys.
-   Accidental infinite loops.
-   Unbounded tool/model cycles.
-   Repeated side effects after retries or resume.
-   Clear stopping criteria and sensible maximum-step limits where
    appropriate.

Do not add a multi-agent supervisor, planner, or complex tool loop
unless the use case benefits from it.

## 6. Configure persistence and memory

Choose persistence based on the required behavior:

-   **No checkpointer:** stateless one-shot execution.
-   **In-memory checkpointer:** local experiments and tests; state is
    lost when the process exits.
-   **Database-backed checkpointer:** durable state for production or
    multi-process deployments.
-   **Store:** long-term application data shared across threads, such as
    user preferences, when the application needs it.

A minimal development example:

``` python
from langgraph.checkpoint.memory import InMemorySaver

checkpointer = InMemorySaver()
graph = builder.compile(checkpointer=checkpointer)

config = {"configurable": {"thread_id": "example-thread"}}
result = graph.invoke({"message": "hello", "result": ""}, config)
```

When a checkpointer is enabled, supply a stable `thread_id` in
`configurable` for each conversation or workflow. Do not use one shared
thread ID for unrelated users. Use a persistent checkpointer in
production; never describe in-memory persistence as durable.

For a database checkpointer:

1.  Install the documented package for the selected database.
2.  Follow the official setup/migration procedure for the installed
    version.
3.  Keep the connection string in a secret environment variable.
4.  Configure connection pooling, cleanup, retention, backups, and
    access control.
5.  Test restart/resume behavior and concurrent access.
6.  Review checkpoint serialization security. Restrict deserialization
    to trusted/allowed types where supported.

Do not put sensitive information in checkpoints unless retention,
authorization, and deletion behavior are understood.

## 7. Use messages and tools correctly

If building a conversational agent, prefer the official message/state
patterns for the installed LangGraph version (for example,
`MessagesState` or an explicit message field with the appropriate
reducer).

When integrating tools:

-   Give each tool a narrow purpose and validated input schema.
-   Treat tool output and retrieved documents as untrusted data, not
    instructions.
-   Apply authorization checks outside the model's control.
-   Validate arguments and constrain filesystem, network, database, and
    account access.
-   Add timeouts and bounded retries for external services.
-   Make side-effecting operations idempotent where possible.
-   Require human confirmation for high-impact or irreversible actions.

Do not expose credentials, private prompts, internal state, or sensitive
tool output in user-facing responses or logs.

## 8. Human-in-the-loop workflows

Use LangGraph's interrupt/resume mechanisms when a workflow needs a
human decision, review, or approval. Verify the current API against the
installed version.

-   Compile with a checkpointer when required for resuming.
-   Use a stable `thread_id` when pausing and resuming.
-   Clearly separate proposed actions from executed actions.
-   Revalidate permissions and the proposed action when resuming; do not
    blindly trust stale approval data.
-   Test both approval and rejection paths, as well as interruption and
    resume after a process restart.
-   Never claim an external action succeeded until the tool or service
    confirms it.

## 9. Async execution, streaming, and errors

Use synchronous `invoke`/`stream` for synchronous code and asynchronous
`ainvoke`/`astream` for async applications. Avoid blocking calls inside
async nodes.

Configure streaming only when the user interface or consumer needs
incremental output, progress, or state updates. Choose the stream mode
intentionally and handle partial events safely.

For errors:

-   Catch expected exceptions at the appropriate boundary.
-   Retry transient failures only, with bounded backoff.
-   Do not retry validation, authorization, or other permanent errors
    blindly.
-   Add timeouts to network and model calls.
-   Return safe error messages to users while retaining useful
    diagnostic context in protected logs.
-   Make it clear which node or external dependency failed.

## 10. Configuration and observability

Use a typed configuration object or a clearly documented `configurable`
schema for runtime values such as model choice, tenant identifier,
feature flags, or limits. Avoid mixing per-run configuration with
persistent graph state.

When useful, enable LangSmith tracing using environment configuration,
but do not enable it by default if it would violate privacy or
data-handling requirements. Redact sensitive values from traces and
logs.

Record enough information to diagnose behavior:

-   Run/thread identifier, node name, duration, and status.
-   External service failures and retry counts.
-   Safe summaries of routing decisions.
-   Token or cost metrics when available and appropriate.

Never log API keys, authorization headers, full sensitive user records,
or unredacted health/financial data.

## 11. Testing checklist

Add tests before calling the configuration complete.

-   [ ] The graph imports and compiles.
-   [ ] A basic input produces the expected output.
-   [ ] Each conditional route is covered.
-   [ ] Missing, malformed, and boundary inputs are handled.
-   [ ] Node failures and external-service timeouts are handled safely.
-   [ ] Loops terminate within expected limits.
-   [ ] Checkpointed runs resume with the correct thread.
-   [ ] Different users/threads do not share private state.
-   [ ] Human approval and rejection paths behave correctly, if used.
-   [ ] Secrets are not committed or printed.
-   [ ] Dependency versions are reproducible.
-   [ ] README setup instructions work in a clean environment.

Prefer unit tests for nodes and routing functions, plus integration
tests for graph execution and persistence. Mock external model and tool
calls in unit tests.

## 12. Troubleshooting guide

**Import error or missing symbol** - Check the installed package version
and interpreter. - Confirm the virtual environment is active. - Compare
the import path with documentation for that version.

**Graph does not terminate** - Inspect conditional route outputs and
cycles. - Add explicit stop conditions and bounded iteration. - Log node
transitions without logging sensitive state.

**State disappears between runs** - Confirm the graph was compiled with
a checkpointer. - Confirm the same intended `thread_id` is passed on
each run. - Replace in-memory persistence with a database-backed
checkpointer if state must survive restarts.

**Threads appear to share memory** - Generate a unique, authorized
thread ID for each conversation. - Check that application code is not
reusing a global ID or leaking state outside the graph. - Enforce
tenant/user authorization independently of thread IDs.

**Checkpoint serialization fails** - Remove non-serializable runtime
objects from state. - Store references/IDs rather than live clients or
handles. - Check serializer restrictions and the selected checkpointer's
supported types.

**Async or streaming hangs** - Check for synchronous blocking calls in
async nodes. - Add timeouts and inspect event consumption. - Verify that
the consumer handles the chosen streaming mode and terminal events.

## 13. Deployment guidance

For local development, a simple Python entry point and in-memory
persistence may be sufficient. For production:

-   Pin tested dependency versions.
-   Use a persistent checkpointer when durability is required.
-   Configure secrets, database connectivity, logging, and monitoring
    outside source code.
-   Define health checks, resource limits, concurrency limits, and
    graceful shutdown.
-   Test migrations, recovery, and deployment rollback.
-   Use LangGraph CLI/Agent Server only if the project needs that
    deployment model; follow its current official configuration format
    rather than inventing a `langgraph.json`.
-   Document local run, test, and deployment commands.

## 14. Expected output when using this skill

When asked to configure a repository, deliver:

1.  A short summary of the current setup and any assumptions.
2.  The concrete files changed and why.
3.  Installation and run commands tailored to the detected environment.
4.  Tests executed and their actual results.
5.  Remaining limitations, security concerns, and production steps.

Do not claim tests passed unless they were run. Do not rewrite unrelated
files or silently introduce new infrastructure.

## Official references

-   LangGraph Python overview:
    https://reference.langchain.com/python/langgraph/overview
-   LangGraph documentation:
    https://docs.langchain.com/oss/python/langgraph/overview
-   Persistence and memory:
    https://docs.langchain.com/oss/python/langgraph/persistence
-   Add memory:
    https://docs.langchain.com/oss/python/langgraph/add-memory
-   LangGraph CLI / deployment: https://docs.langchain.com/langsmith/cli
