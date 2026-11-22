from nicegui import ui

# State management for view switching
current_view = "login"


def switch_view(view_name):
    global current_view
    current_view = view_name
    main_container.clear()
    with main_container:
        if current_view == "login":
            build_login_view()
        elif current_view == "dashboard":
            build_dashboard_view()
        elif current_view == "scans":
            build_scans_view()
        elif current_view == "admin":
            build_admin_view()


# --- View 1: Login Screen ---
def build_login_view():
    with ui.card().classes(
        "absolute-center w-96 p-8 shadow-2xl rounded-xl bg-slate-900 text-white"
    ):
        ui.label("Aegis Project").classes("text-2xl font-bold text-center w-full")
        ui.label("Automated VAPT Engine").classes(
            "text-xs text-slate-400 text-center w-full mb-6"
        )

        ui.input("Username").classes("w-full mb-4")
        ui.input("Password", password=True, password_toggle_button=True).classes(
            "w-full mb-6"
        )

        ui.button("Log In", on_click=lambda: switch_view("dashboard")).classes(
            "w-full bg-blue-600 text-white font-semibold py-2 rounded-lg"
        )

        with ui.row().classes("w-full justify-between mt-4 text-xs text-slate-400"):
            ui.link("Forgot Password?", "#").classes("text-slate-400")
            ui.link("Two-Factor Authentication", "#").classes("text-slate-400")


# --- View 2: Dashboard Overview ---
def build_dashboard_view():
    with ui.row().classes("w-full items-center mb-6"):
        ui.label("Dashboard Overview").classes(
            "text-2xl font-bold text-slate-800 dark:text-white"
        )

    # Metrics Grid
    with ui.row().classes("w-full gap-4 mb-6"):
        with ui.card().classes("flex-1 p-4 bg-white shadow rounded-lg"):
            ui.label("Total Scans").classes("text-sm text-slate-500")
            ui.label("120").classes("text-3xl font-bold text-slate-800")
        with ui.card().classes("flex-1 p-4 bg-white shadow rounded-lg"):
            ui.label("Critical Issues").classes("text-sm text-slate-500")
            ui.label("15").classes("text-3xl font-bold text-red-600")
        with ui.card().classes("flex-1 p-4 bg-white shadow rounded-lg"):
            ui.label("Overall Risk Score").classes("text-sm text-slate-500")
            ui.label("High").classes("text-3xl font-bold text-orange-500")

    # Recent Alerts & Trends layout
    with ui.row().classes("w-full gap-4"):
        with ui.card().classes("flex-2 p-4 bg-white shadow rounded-lg w-3/5"):
            ui.label("Vulnerability Trend").classes("font-bold mb-2")
            ui.linear_progress(value=0.7, show_value=False).classes("mt-4")
        with ui.card().classes("flex-1 p-4 bg-white shadow rounded-lg w-2/5"):
            ui.label("Recent Alerts").classes("font-bold mb-2")
            ui.label("• High Risk: SQL Injection Detected").classes(
                "text-xs text-red-500 mt-2"
            )
            ui.label("• Medium Risk: Outdated Software").classes(
                "text-xs text-orange-500 mt-2"
            )
            ui.label("• Low Risk: Open Port Found").classes(
                "text-xs text-blue-500 mt-2"
            )


# --- View 3: Scan Management ---
def build_scans_view():
    ui.label("Scan Management").classes(
        "text-2xl font-bold mb-4 text-slate-800 dark:text-white"
    )
    with ui.card().classes("w-full p-6 bg-white shadow rounded-lg mb-6"):
        ui.label("Start a New Scan").classes("font-bold mb-4")
        ui.input("Target IP Range").classes("w-full mb-4")
        ui.select(
            ["Quick Scan", "Full VAPT", "Custom Port Scan"], value="Quick Scan"
        ).classes("w-full mb-4")
        ui.button("Start Scan").classes("bg-blue-600 text-white")

    # Active Scans Table
    ui.table(
        columns=[
            {
                "name": "name",
                "label": "Scan Name",
                "field": "name",
                "required": True,
            },
            {"name": "status", "label": "Status", "field": "status"},
            {"name": "initiator", "label": "Initiated By", "field": "initiator"},
        ],
        rows=[
            {
                "name": "Network Scan 001",
                "status": "Running",
                "initiator": "Admin",
            },
            {"name": "Web Scan 002", "status": "Completed", "initiator": "User1"},
            {"name": "Internal Audit 003", "status": "Queued", "initiator": "Admin"},
        ],
    ).classes("w-full bg-white shadow rounded-lg")


# --- View 4: Admin & Settings ---
def build_admin_view():
    ui.label("Admin & Settings").classes(
        "text-2xl font-bold mb-4 text-slate-800 dark:text-white"
    )
    with ui.card().classes("w-full p-6 bg-white shadow rounded-lg"):
        ui.label("User Management").classes("font-bold mb-4")
        ui.button("Add User", icon="person_add").classes("bg-green-600 text-white")


# --- Main Layout Framework ---
with ui.left_drawer().classes("bg-slate-800 text-white p-4"):
    ui.label("Aegis VAPT").classes("text-xl font-bold mb-6")
    ui.button(
        "Dashboard", on_click=lambda: switch_view("dashboard")
    .classes("w-full text-left mb-2 bg-transparent"))
    ui.button(
        "Scans", on_click=lambda: switch_view("scans")
    .classes("w-full text-left mb-2 bg-transparent"))
    ui.button(
        "Admin", on_click=lambda: switch_view("admin")
    .classes("w-full text-left mb-2 bg-transparent"))
    ui.button(
        "Logout", on_click=lambda: switch_view("login")
    .classes("w-full text-left text-red-400 bg-transparent mt-10"))

# Dynamic Container where views load
main_container = ui.column().classes("w-full p-8 bg-slate-100 min-h-screen")

# Initialize default view
build_login_view()

ui.run(port=8080)
