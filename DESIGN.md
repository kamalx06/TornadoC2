# C2 Framework GUI/UX Design Specification & Architecture

## 1. Core Aesthetic & Theme
- **Theme:** Strictly Dark Mode. Pitch-black and deep gray backgrounds (`#0A0A0A` for main background, `#121212` for panels, `#1E1E1E` for headers).
- **Accent Colors:** High-contrast neon colors used *sparingly* for status indicators, active tabs, and syntax highlighting. (e.g., Cyan `#00E5FF` for active/connected, Green `#00FF00` for success, Red `#FF0033` for danger/kill).
- **Typography:** Modern sans-serif (Inter, Roboto) for UI text. Monospaced fonts (JetBrains Mono, Fira Code) for Terminals, Data Grids, and Logs.
- **Density:** High information density (Cobalt Strike style). Minimal padding, crisp 1px borders, no rounded corners on data grids.

## 2. Layout & Docking Architecture
- **Docking System:** The UI is a flexible, multi-pane docking workspace (similar to VS Code or Cobalt Strike). Users can drag tabs out to create detached windows, or dock them into any pane.
- **Top Navigation Bar:** 
  - Left: Main menu (File, View, Tabs, Help).
  - Center/Right: Quick actions (Build, Palette, Jump, Detach, Disconnect).
  - Far Right: Status metrics, clock, and Workspace selector (e.g., `Workspace 1`).
- **Default Workspaces:** The 18 panels will be grouped logically into tabs within these workspaces.

## 3. Workspace Layouts (The 18 Panels)

### Workspace 1: Target Operations (Default 2x2 Grid)
This is the primary operational view.
- **Top-Left Pane: Screen & Graph (Tabbed)**
  - **Tab 1: Screen.** PNG screenshot stage, zoom/pan controls, interval capture, download.
  - **Tab 2: Graph.** Canvas force graph, typed edges, clustering toggle, minimap, hover cards.
- **Top-Right Pane: Terminal**
  - **Tab 1: Terminal.** Console output, per-target transcript, prompt combobox, verb listbox, raw toggle, shell start/stop.
- **Bottom-Left Pane: Host Data Grids**
  - **Tab 1: Processes.** Tree/Flat view, columns (PID, Process, Command), kill action.
  - **Tab 2: Files.** Path bar with breadcrumbs, columns (Name, Type, Path), double-click to open, download action.
  - **Tab 3: Network.** Columns (Proto, Local, Remote, State, PID, Process), kill action.
- **Bottom-Right Pane: Roster & Inspector**
  - **Tab 1: Targets.** Virtualized roster, severity sort, filter, bulk actions (Task/Tag/Kill), inline alias edit.
  - **Tab 2: Inspector.** Collapsible sections (Identity, Session, Execution, Payloads, Notes, Transfer, Pivot, Danger).

### Workspace 2: Infrastructure & Assets
- **Tab: Listeners.** DataGrid with (Name, Type, Bind, TLS, State, Health, Cert, Probes sparkline). Includes side-sheet for Create/Edit.
- **Tab: Armory.** Catalogue view (Installed count, Update index). URL-based system replacing old signing. Columns (Name, Format, Description, Action).
- **Tab: Credentials.** Masked values, reveal button.
- **Tab: Settings.** Theme, density, AI provider form, shortcut table.

### Workspace 3: Comms & Telemetry
- **Tab: Events.** Merged bridge/task/audit ring, pause/follow, filters, save.
- **Tab: Chat.** Operator chat, day rules, topic header, retry on failure.
- **Tab: Audit.** Hash-chain audit reader, verify button.
- **Tab: Jobs.** Upload/download/build progress bars, cancel action.
- **Tab: AI.** Sleek AI console with turn log, question input, and "Ask" button.

### Workspace 4: Intel & Reporting
- **Tab: Engagement.** Model tabs (Hosts, Users, Shares, Services, Evidence, Findings, Timeline). IOC/STIX/Report export.
- **Tab: Targets.** (Duplicated for convenience).

## 4. Specific UI/UX Upgrades & Fixes
1.  **Armory Overhaul:** Remove all signing/verification UI (`ARMORY_BASE`, `_armory_verify`). Replace with a clean URL-input field and a list of available/installed extensions with Install/Uninstall/Update buttons.
2.  **Listener Management:** The Side-Sheet must be expanded to support all bridge types (`icmp`, `wireguard`, `quic`, `websocket`, `subnet`, `server_ip`, `dns`, `icmp_host`, `http` and others which are supported), with proper validation fields.
3.  **Teamserver Log Noise:** Do NOT print HTTP requests (`POST /api/v1/beacons`) to the CLI. Redirect them to the **Events** tab in the GUI.
4.  **AI Chat Terminal:** Needs a modern chat UI (distinct operator vs. AI bubbles, markdown rendering, loading state).
5.  **Operator Config:** When an operator is added, auto-export and print the config securely.