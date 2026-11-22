import asyncio
import json
import logging
import os
from datetime import datetime
from fastapi import FastAPI
from nicegui import ui, app
import uvicorn

from scanner import scan_target, analyze_results

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AegisEngine")

# Initialize FastAPI app
fastapi_app = FastAPI(title="Aegis VAPT Engine")

USER_DB_FILE = "users.json"
SCANS_DB_FILE = "scans.json"
SYSTEM_CONFIG_FILE = "config.json"

PG_CONFIG = {
    "host": os.getenv("AEGIS_PG_HOST", "127.0.0.1"),
    "port": int(os.getenv("AEGIS_PG_PORT", "5433")),
    "dbname": os.getenv("AEGIS_PG_DB", "aegis_vapt"),
    "user": os.getenv("AEGIS_PG_USER", "aegis_admin"),
    "password": os.getenv("AEGIS_PG_PASSWORD", "securepassword"),
}

def _get_pg_conn():
    try:
        import psycopg2
        conn = psycopg2.connect(**PG_CONFIG, connect_timeout=3)
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username VARCHAR(120) PRIMARY KEY,
                    password TEXT NOT NULL,
                    role VARCHAR(64) NOT NULL DEFAULT 'Analyst',
                    data JSONB NOT NULL DEFAULT '{}'::jsonb
                );
                """
            )
        conn.commit()
        return conn
    except Exception as e:
        logger.warning(f"PostgreSQL unavailable, using JSON fallback: {e}")
        return None

def load_users():
    conn = _get_pg_conn()
    if conn is not None:
        try:
            import json as _json
            users_map = {}
            with conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT username, password, role, data FROM users;")
                    for uname, pw, role, extra in cur.fetchall():
                        entry = dict(extra) if isinstance(extra, dict) else (_json.loads(extra) if extra else {})
                        entry.setdefault("password", pw or "")
                        entry.setdefault("role", role or "Analyst")
                        entry.setdefault("status", "Active")
                        users_map[uname] = entry
            if users_map:
                return users_map
        except Exception as e:
            logger.error(f"Error loading users from PostgreSQL: {e}")
        finally:
            conn.close()
    if os.path.exists(USER_DB_FILE):
        try:
            with open(USER_DB_FILE, "r") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except Exception as e:
            logger.error(f"Error loading users.json: {e}")
    return {}

def save_users(users):
    if not isinstance(users, dict):
        return
    conn = _get_pg_conn()
    if conn is not None:
        try:
            import json as _json
            with conn:
                with conn.cursor() as cur:
                    for uname, info in users.items():
                        payload = info if isinstance(info, dict) else {"value": info}
                        pw = str(payload.get("password", ""))
                        role = str(payload.get("role", "Analyst"))
                        cur.execute(
                            """
                            INSERT INTO users (username, password, role, data)
                            VALUES (%s, %s, %s, %s::jsonb)
                            ON CONFLICT (username) DO UPDATE
                            SET password = EXCLUDED.password,
                                role = EXCLUDED.role,
                                data = EXCLUDED.data;
                            """,
                            (uname, pw, role, _json.dumps(payload)),
                        )
            return
        except Exception as e:
            logger.error(f"Error saving users to PostgreSQL: {e}")
        finally:
            conn.close()
    try:
        with open(USER_DB_FILE, "w") as f:
            json.dump(users, f, indent=4)
    except Exception as e:
        logger.error(f"Error saving users.json: {e}")

def _ensure_state_table(conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS app_state (
                state_key VARCHAR(64) PRIMARY KEY,
                payload JSONB NOT NULL
            );
            """
        )
    conn.commit()

def load_scans():
    conn = _get_pg_conn()
    if conn is not None:
        try:
            import json as _json
            _ensure_state_table(conn)
            with conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT payload FROM app_state WHERE state_key = 'scan_history';")
                    row = cur.fetchone()
                    if row and row[0] is not None:
                        data = row[0] if isinstance(row[0], list) else _json.loads(row[0])
                        if isinstance(data, list):
                            return data
        except Exception as e:
            logger.error(f"Error loading scans from PostgreSQL: {e}")
        finally:
            conn.close()
    if os.path.exists(SCANS_DB_FILE):
        try:
            with open(SCANS_DB_FILE, "r") as f:
                data = json.load(f)
                if isinstance(data, list):
                    save_scans(data)
                    return data
        except Exception as e:
            logger.error(f"Error loading scans.json: {e}")
    return []

def save_scans(scans):
    conn = _get_pg_conn()
    if conn is not None:
        try:
            import json as _json
            _ensure_state_table(conn)
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO app_state (state_key, payload)
                        VALUES ('scan_history', %s::jsonb)
                        ON CONFLICT (state_key) DO UPDATE
                        SET payload = EXCLUDED.payload;
                        """,
                        (_json.dumps(scans),),
                    )
            return
        except Exception as e:
            logger.error(f"Error saving scans to PostgreSQL: {e}")
        finally:
            conn.close()
    try:
        with open(SCANS_DB_FILE, "w") as f:
            json.dump(scans, f, indent=4)
    except Exception as e:
        logger.error(f"Error saving scans.json: {e}")

def load_system_config():
    conn = _get_pg_conn()
    if conn is not None:
        try:
            import json as _json
            _ensure_state_table(conn)
            with conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT payload FROM app_state WHERE state_key = 'system_config';")
                    row = cur.fetchone()
                    if row and row[0] is not None:
                        data = row[0] if isinstance(row[0], dict) else _json.loads(row[0])
                        if isinstance(data, dict):
                            return data
        except Exception as e:
            logger.error(f"Error loading system_config from PostgreSQL: {e}")
        finally:
            conn.close()
    if os.path.exists(SYSTEM_CONFIG_FILE):
        try:
            with open(SYSTEM_CONFIG_FILE, "r") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    save_system_config(data)
                    return data
        except Exception as e:
            logger.error(f"Error loading config.json: {e}")
    return {"app_disabled": False}

def save_system_config(config):
    conn = _get_pg_conn()
    if conn is not None:
        try:
            import json as _json
            _ensure_state_table(conn)
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO app_state (state_key, payload)
                        VALUES ('system_config', %s::jsonb)
                        ON CONFLICT (state_key) DO UPDATE
                        SET payload = EXCLUDED.payload;
                        """,
                        (_json.dumps(config),),
                    )
            return
        except Exception as e:
            logger.error(f"Error saving system_config to PostgreSQL: {e}")
        finally:
            conn.close()
    try:
        with open(SYSTEM_CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        logger.error(f"Error saving config.json: {e}")

registered_users = load_users()
scan_history = load_scans()
system_config = load_system_config()

active_scans_db = {}
task_references = {}
scan_queue = []
active_sessions = set()

def get_session_user():
    if "authenticated" not in app.storage.user:
        app.storage.user.update({
            "authenticated": False,
            "username": "",
            "role": "Analyst"
        })
    return app.storage.user

def is_master_admin(user_session):
    uname = user_session.get("username")
    if uname in registered_users and registered_users[uname].get("role") == "Administrator":
        return True
    return user_session.get("role") == "Administrator"

def check_app_status():
    cfg = load_system_config()
    return cfg.get("app_disabled", False)

# ---------------- Shared Shield Logo Component ----------------
def render_shield_logo(title_text="AEGIS VAPT"):
    with ui.row().classes('items-center justify-center gap-3 mb-4'):
        ui.html('''
            <div style="position: relative; display: flex; align-items: center; justify-content: center; width: 52px; height: 52px; background: radial-gradient(circle, rgba(239,68,68,0.2) 0%, rgba(15,23,42,1) 80%); border-radius: 12px; border: 1px solid rgba(239,68,68,0.4); box-shadow: 0 0 15px rgba(239,68,68,0.3);">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                    <circle cx="12" cy="11" r="3"></circle>
                    <path d="M12 8v-2"></path>
                </svg>
            </div>
        ''')
        with ui.column().classes('gap-0'):
            ui.label(title_text).classes('text-xl font-mono font-bold tracking-widest text-transparent bg-clip-text bg-gradient-to-r from-red-500 via-orange-400 to-yellow-400')
            ui.label('SECURE VAPT PLATFORM').classes('text-[10px] font-mono tracking-wider text-blue-400 font-semibold')

# ---------------- Sidebar with Iconography ----------------
def create_sidebar():
    user_session = get_session_user()
    with ui.column().classes('w-64 bg-gray-900 h-screen p-4 gap-2 border-r border-gray-800 shrink-0'):
        render_shield_logo("AEGIS VAPT")
        ui.separator().classes('my-2 bg-gray-800')
        
        ui.button('👤 Dashboard', on_click=lambda: ui.run_javascript('window.location.href = "/"')).classes('w-full bg-transparent text-gray-300 hover:text-white hover:bg-gray-800 shadow-none justify-start font-mono text-xs')
        ui.button('📡 Scans', on_click=lambda: ui.run_javascript('window.location.href = "/scans"')).classes('w-full bg-transparent text-gray-300 hover:text-white hover:bg-gray-800 shadow-none justify-start font-mono text-xs')
        ui.button('💼 Reports', on_click=lambda: ui.run_javascript('window.location.href = "/reports"')).classes('w-full bg-transparent text-gray-300 hover:text-white hover:bg-gray-800 shadow-none justify-start font-mono text-xs')
        ui.button('🔧 Settings', on_click=lambda: ui.run_javascript('window.location.href = "/settings"')).classes('w-full bg-transparent text-gray-300 hover:text-white hover:bg-gray-800 shadow-none justify-start font-mono text-xs')
        
        if is_master_admin(user_session):
            ui.button('💻 Admin Control', on_click=lambda: ui.run_javascript('window.location.href = "/admin"')).classes('w-full bg-transparent text-gray-300 hover:text-white hover:bg-gray-800 shadow-none justify-start font-mono text-xs')
            
        ui.space()

        def logout():
            uname = user_session.get("username")
            if uname in active_sessions:
                active_sessions.remove(uname)
            app.storage.user.clear()
            ui.run_javascript('window.location.href = "/login"')

        ui.button('Log Out', on_click=logout).classes('w-full bg-red-600 hover:bg-red-700 text-white mt-auto font-mono text-xs')

# ---------------- Disabled Lockout Page ----------------
@ui.page('/locked')
def locked_page():
    with ui.card().classes('absolute-center w-96 p-8 shadow-2xl bg-gradient-to-br from-red-950 via-gray-900 to-gray-950 border border-red-800 text-white text-center'):
        render_shield_logo("SYSTEM LOCKED")
        ui.label('The platform has been disabled by an administrator.').classes('text-xs font-mono text-gray-300 mb-6')
        
        if is_master_admin(get_session_user()):
            def restore_app():
                cfg = load_system_config()
                cfg["app_disabled"] = False
                save_system_config(cfg)
                ui.notify('Platform successfully reactivated!', type='positive')
                ui.run_javascript('window.location.href = "/"')
            ui.button('Re-enable Application', on_click=restore_app).classes('w-full bg-blue-600 hover:bg-blue-700 text-white font-mono text-xs')

# ---------------- Register Page ----------------
@ui.page('/register')
def register_page():
    if check_app_status():
        return ui.run_javascript('window.location.href = "/locked"')
        
    user_session = get_session_user()
    if user_session.get("authenticated"):
        return ui.run_javascript('window.location.href = "/"')

    with ui.card().classes('absolute-center w-[420px] p-8 shadow-2xl bg-gradient-to-br from-gray-900 via-gray-950 to-slate-900 border border-gray-700 text-white'):
        render_shield_logo("AEGIS ACCESS")
        ui.label('Create Operator Account').classes('text-xs font-mono text-blue-400 text-center w-full mb-6 tracking-widest uppercase')
        
        reg_username = ui.input(label='Choose Username', placeholder='Enter username').classes('w-full mb-4 text-white').props('dark outlined')
        reg_password = ui.input(label='Choose Password', placeholder='Enter password', password=True, password_toggle_button=True).classes('w-full mb-6 text-white').props('dark outlined')
        
        def handle_register():
            uname = reg_username.value.strip()
            pword = reg_password.value.strip()
            
            if not uname or not pword:
                ui.notify('All fields are required.', type='negative')
                return
                
            global registered_users
            registered_users = load_users()
                
            if uname in registered_users:
                ui.notify('Username already exists. Choose another.', type='negative')
                return
                
            assigned_role = "Administrator" if not registered_users else "Analyst"
                
            registered_users[uname] = {"password": pword, "role": assigned_role, "status": "Active"}
            save_users(registered_users)
            
            ui.notify('Account successfully created! Please log in.', type='positive')
            ui.run_javascript('window.location.href = "/login"')

        ui.button('Register Account', on_click=handle_register).classes('w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white font-mono mb-4 text-xs py-3 shadow-lg')
        
        with ui.row().classes('w-full justify-center text-xs'):
            ui.link('Already have an account? Log In', '/login').classes('text-gray-400 hover:text-white')

# ---------------- Forgot Password Page ----------------
@ui.page('/forgot-password')
def forgot_password_page():
    if check_app_status():
        return ui.run_javascript('window.location.href = "/locked"')

    with ui.card().classes('absolute-center w-[420px] p-8 shadow-2xl bg-gradient-to-br from-gray-900 via-gray-950 to-slate-900 border border-gray-700 text-white'):
        render_shield_logo("AEGIS RECOVERY")
        ui.label('Password Recovery Sequence').classes('text-xs font-mono text-yellow-400 text-center w-full mb-6 tracking-widest uppercase')
        
        target_uname = ui.input(label='Operator Username', placeholder='Enter username').classes('w-full mb-4 text-white').props('dark outlined')
        new_pass_input = ui.input(label='New Password', placeholder='Enter new password', password=True, password_toggle_button=True).classes('w-full mb-6 text-white').props('dark outlined')

        def handle_reset():
            uname = target_uname.value.strip()
            npword = new_pass_input.value.strip()
            if not uname or not npword:
                ui.notify('All fields are required.', type='negative')
                return

            global registered_users
            registered_users = load_users()
            if uname not in registered_users:
                ui.notify('Username not found in system records.', type='negative')
                return

            registered_users[uname]["password"] = npword
            save_users(registered_users)
            ui.notify('Password reset successfully. Please log in.', type='positive')
            ui.run_javascript('window.location.href = "/login"')

        ui.button('Reset Password', on_click=handle_reset).classes('w-full bg-gradient-to-r from-yellow-600 to-orange-600 hover:from-yellow-700 hover:to-orange-700 text-white font-mono mb-4 text-xs py-3 shadow-lg')
        
        with ui.row().classes('w-full justify-center text-xs'):
            ui.link('Back to Log In', '/login').classes('text-gray-400 hover:text-white font-mono')

# ---------------- Colorful, Polished Login Page ----------------
@ui.page('/login')
def login_page():
    if check_app_status():
        return ui.run_javascript('window.location.href = "/locked"')

    try:
        user_session = get_session_user()
        if user_session.get("authenticated"):
            return ui.run_javascript('window.location.href = "/"')

        with ui.row().classes('w-full h-screen items-center justify-center bg-gradient-to-tr from-gray-950 via-slate-900 to-indigo-950 relative overflow-hidden'):
            ui.html('''
                <div style="position: absolute; top: -10%; left: -10%; width: 40vw; height: 40vw; background: rgba(239, 68, 68, 0.15); filter: blur(120px); border-radius: 50%; pointer-events: none;"></div>
                <div style="position: absolute; bottom: -10%; right: -10%; width: 40vw; height: 40vw; background: rgba(59, 130, 246, 0.15); filter: blur(120px); border-radius: 50%; pointer-events: none;"></div>
            ''')

            with ui.card().classes('w-[420px] p-8 bg-gray-900/90 backdrop-blur-md text-white border border-gray-700/80 shadow-2xl rounded-xl relative z-10'):
                render_shield_logo("AEGIS VAPT")
                ui.label('Advanced Vulnerability Assessment & Penetration Testing').classes('text-[11px] font-mono text-gray-400 text-center w-full mb-6 tracking-wide')
                
                username_input = ui.input(label='Operator Username', placeholder='Enter username').classes('w-full mb-4 text-white').props('dark outlined')
                password_input = ui.input(label='Security Password', placeholder='Enter password', password=True, password_toggle_button=True).classes('w-full mb-6 text-white').props('dark outlined')

                def handle_login():
                    uname, pword = username_input.value.strip(), password_input.value.strip()
                    global registered_users
                    registered_users = load_users()
                    
                    if uname in registered_users:
                        user_record = registered_users[uname]
                        if user_record.get("status") in ["Suspended", "Deactivated"]:
                            ui.notify('Account is deactivated or suspended. Contact administrator.', type='negative')
                            return
                        if user_record["password"] == pword:
                            app.storage.user.update({
                                "authenticated": True,
                                "username": uname,
                                "role": user_record["role"]
                            })
                            active_sessions.add(uname)
                            ui.notify('Authentication successful.', type='positive')
                            ui.run_javascript('window.location.href = "/"')
                            return
                    ui.notify('Invalid username or password.', type='negative')

                ui.button('LOG IN', on_click=handle_login).classes('w-full bg-gradient-to-r from-red-600 via-orange-600 to-red-700 hover:from-red-700 hover:to-orange-700 text-white font-mono mb-4 text-xs py-3 shadow-lg tracking-wider')
                
                with ui.row().classes('w-full justify-between text-xs mt-2'):
                    ui.link('Create Account', '/register').classes('text-blue-400 hover:text-blue-300 font-mono')
                    ui.link('Forgot Password?', '/forgot-password').classes('text-yellow-400 hover:text-yellow-300 font-mono')
    except Exception as e:
        logger.error(f"Login page error: {e}")
        ui.label("Login page failed").classes('text-red-500')

# ---------------- Dashboard Overview (Direct Tile Redirection) ----------------
@ui.page('/')
def dashboard_overview():
    if check_app_status():
        return ui.run_javascript('window.location.href = "/locked"')

    try:
        user_session = get_session_user()
        if not user_session.get("authenticated"):
            return ui.run_javascript('window.location.href = "/login"')

        current_user = user_session.get("username")
        if current_user not in active_sessions:
            active_sessions.add(current_user)

        with ui.row().classes('w-full h-screen no-wrap bg-gray-950'):
            create_sidebar()
            with ui.column().classes('flex-grow p-8 text-white overflow-y-auto'):
                ui.label('👤 Dashboard Overview & Quick Actions').classes('text-2xl font-mono font-bold mb-2')
                ui.label('Select a module below or review your active operator session.').classes('text-xs font-mono text-gray-400 mb-8')
                
                with ui.row().classes('w-full gap-6 mb-6'):
                    with ui.card().classes('p-6 flex-grow bg-gray-900 border border-gray-800'):
                        ui.label('Active Operator Session').classes('text-gray-400 font-mono text-xs')
                        ui.label(current_user).classes('text-3xl font-mono font-bold text-red-500 mt-2')

                with ui.row().classes('w-full gap-4 mb-6'):
                    with ui.card().classes('cursor-pointer p-5 bg-gray-900 hover:bg-gray-800 border border-red-900/50 hover:border-red-600 flex-grow text-center items-center rounded transition-all').on('click', lambda: ui.run_javascript('window.location.href = "/scans"')):
                        ui.label('📡').classes('text-2xl mb-1')
                        ui.label('Initialize Scan').classes('font-mono text-xs font-bold text-red-400')

                    with ui.card().classes('cursor-pointer p-5 bg-gray-900 hover:bg-gray-800 border border-blue-900/50 hover:border-blue-600 flex-grow text-center items-center rounded transition-all').on('click', lambda: ui.run_javascript('window.location.href = "/reports"')):
                        ui.label('💼').classes('text-2xl mb-1')
                        ui.label('View Reports').classes('font-mono text-xs font-bold text-blue-400')

                    with ui.card().classes('cursor-pointer p-5 bg-gray-900 hover:bg-gray-800 border border-yellow-900/50 hover:border-yellow-600 flex-grow text-center items-center rounded transition-all').on('click', lambda: ui.run_javascript('window.location.href = "/settings"')):
                        ui.label('🔧').classes('text-2xl mb-1')
                        ui.label('Settings').classes('font-mono text-xs font-bold text-yellow-400')

    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        ui.label("Dashboard failed").classes('text-red-500')

# ---------------- User Settings (Organized Card Layout) ----------------
@ui.page('/settings')
def user_settings_page():
    if check_app_status():
        return ui.run_javascript('window.location.href = "/locked"')

    try:
        user_session = get_session_user()
        if not user_session.get("authenticated"):
            return ui.run_javascript('window.location.href = "/login"')

        current_user = user_session.get("username")
        if current_user not in active_sessions:
            active_sessions.add(current_user)

        with ui.row().classes('w-full h-screen no-wrap bg-gray-950'):
            create_sidebar()
            with ui.column().classes('flex-grow p-8 text-white overflow-y-auto'):
                ui.label('🔧 User Settings & Profile Control').classes('text-2xl font-mono font-bold mb-6')

                with ui.row().classes('w-full gap-6 no-wrap'):
                    with ui.card().classes('p-6 flex-grow bg-gray-900 border border-gray-800'):
                        ui.label('Edit Profile Credentials').classes('font-mono font-bold text-blue-400 mb-4 text-sm')
                        
                        global registered_users
                        registered_users = load_users()

                        new_username_input = ui.input(label='Change Username', value=current_user).classes('w-full mb-4 text-white').props('dark outlined')
                        
                        ui.separator().classes('my-4 bg-gray-800')
                        ui.label('Change Password Security Sequence').classes('font-mono text-xs text-gray-300 mb-2')

                        old_pass_input = ui.input(label='Old / Last Known Password', password=True, password_toggle_button=True).classes('w-full mb-3 text-white').props('dark outlined')
                        new_pass_input = ui.input(label='New Password', password=True, password_toggle_button=True).classes('w-full mb-3 text-white').props('dark outlined')
                        confirm_pass_input = ui.input(label='Confirm New Password', password=True, password_toggle_button=True).classes('w-full mb-4 text-white').props('dark outlined')

                        def save_profile_updates():
                            global registered_users
                            registered_users = load_users()
                            
                            target_user_record = registered_users.get(current_user)
                            if not target_user_record:
                                ui.notify('User record not found.', type='negative')
                                return

                            desired_username = new_username_input.value.strip()
                            old_pword = old_pass_input.value.strip()
                            new_pword = new_pass_input.value.strip()
                            confirm_pword = confirm_pass_input.value.strip()

                            current_user_key = current_user
                            if desired_username and desired_username != current_user:
                                if desired_username in registered_users:
                                    ui.notify('Username is already taken.', type='negative')
                                    return
                                registered_users[desired_username] = registered_users.pop(current_user)
                                current_user_key = desired_username
                                app.storage.user['username'] = desired_username
                                active_sessions.remove(current_user)
                                active_sessions.add(desired_username)

                            if old_pword or new_pword or confirm_pword:
                                if old_pword != registered_users[current_user_key]["password"]:
                                    ui.notify('Old password verification failed. Incorrect password entered.', type='negative')
                                    save_users(registered_users)
                                    return
                                if not new_pword or not confirm_pword:
                                    ui.notify('Please provide and confirm the new password.', type='negative')
                                    return
                                if new_pword != confirm_pword:
                                    ui.notify('New passwords do not match.', type='negative')
                                    return
                                registered_users[current_user_key]["password"] = new_pword
                                ui.notify('Username and password updated successfully.', type='positive')
                            else:
                                ui.notify('Username updated successfully.', type='positive')

                            save_users(registered_users)
                            ui.run_javascript('window.location.reload()')

                        ui.button('Save Profile Changes', on_click=save_profile_updates).classes('bg-blue-600 hover:bg-blue-700 text-white text-xs font-mono')

                    with ui.column().classes('w-96 gap-6 shrink-0'):
                        with ui.card().classes('p-6 w-full bg-gray-900 border border-gray-800'):
                            ui.label('Data Management').classes('font-mono font-bold text-yellow-400 mb-2 text-sm')
                            ui.label('Clear your personal scan history logs from the database.').classes('text-xs text-gray-400 mb-4')

                            def handle_clear_history():
                                global scan_history
                                scan_history = [s for s in scan_history if s.get('initiated_by') != current_user]
                                save_scans(scan_history)
                                ui.notify('Your scan history has been cleared.', type='warning')

                            ui.button('Clear My Scan History', on_click=handle_clear_history).classes('bg-yellow-700 hover:bg-yellow-800 text-white text-xs font-mono')

                        with ui.card().classes('p-6 w-full bg-gray-900 border border-red-900'):
                            ui.label('Danger Zone: Delete Account').classes('font-mono font-bold text-red-500 mb-2 text-sm')
                            ui.label('Permanently remove your operator account and data from the system.').classes('text-xs text-gray-400 mb-4')

                            def handle_self_deletion():
                                global registered_users
                                registered_users = load_users()
                                if current_user in registered_users:
                                    registered_users.pop(current_user, None)
                                    save_users(registered_users)
                                    if current_user in active_sessions:
                                        active_sessions.remove(current_user)
                                    app.storage.user.clear()
                                    ui.notify('Your account has been permanently deleted.', type='warning')
                                    ui.run_javascript('window.location.href = "/login"')

                            ui.button('Delete My Account', on_click=handle_self_deletion).classes('bg-red-900 hover:bg-red-950 text-white text-xs font-mono')

    except Exception as e:
        logger.error(f"Settings page error: {e}")
        ui.label("Settings page failed").classes('text-red-500')

# ---------------- Scan Management & Queue ----------------
@ui.page('/scans')
def scan_management():
    if check_app_status():
        return ui.run_javascript('window.location.href = "/locked"')

    try:
        user_session = get_session_user()
        if not user_session.get("authenticated"):
            return ui.run_javascript('window.location.href = "/login"')

        current_user = user_session.get("username")
        if current_user not in active_sessions:
            active_sessions.add(current_user)

        is_admin = is_master_admin(user_session)

        with ui.row().classes('w-full h-screen no-wrap bg-gray-950'):
            create_sidebar()
            with ui.column().classes('flex-grow p-8 text-white overflow-y-auto'):
                ui.label('📡 Scan Management, Dispatch & Workers').classes('text-2xl font-mono font-bold mb-6')

                with ui.card().classes('w-full p-6 bg-gray-900 border border-gray-800 mb-6'):
                    ui.label('Initialize Background Scan Task').classes('font-mono font-bold text-blue-400 mb-4 text-sm')
                    target_input = ui.input(label='Target IP / Range', placeholder='127.0.0.1', value='127.0.0.1').classes('w-full mb-4 text-white').props('dark outlined')
                    ports_input = ui.input(label='Target Port Scope', placeholder='80,443 or 1-1000', value='80,443,22,8080').classes('w-full mb-4 text-white').props('dark outlined')
                    
                    active_scans_container = ui.column().classes('w-full gap-2')
                    queue_container = ui.column().classes('w-full gap-2')

                    async def run_background_scan(task_id, target, selected_ports, operator_name):
                        try:
                            active_scans_db[task_id].update({"status": "Initializing Target Socket...", "progress": "10%"})
                            await asyncio.sleep(0.8)
                            active_scans_db[task_id].update({"status": "Scanning Port Scope...", "progress": "40%"})
                            
                            if asyncio.iscoroutinefunction(scan_target):
                                raw_data = await scan_target(target, ports=selected_ports)
                            else:
                                loop = asyncio.get_event_loop()
                                raw_data = await loop.run_in_executor(None, lambda: scan_target(target, ports=selected_ports))
                            
                            if task_id not in active_scans_db:
                                return

                            active_scans_db[task_id].update({"status": "Analyzing Vulnerability Heuristics & CVEs...", "progress": "70%"})
                            await asyncio.sleep(0.8)
                            
                            if asyncio.iscoroutinefunction(analyze_results):
                                analyzed_report = await analyze_results(raw_data)
                            else:
                                loop = asyncio.get_event_loop()
                                analyzed_report = await loop.run_in_executor(None, lambda: analyze_results(raw_data))
                            
                            if task_id not in active_scans_db:
                                return

                            findings = []
                            if isinstance(analyzed_report, list):
                                for item in analyzed_report:
                                    severity = item.get('severity')
                                    if not severity or severity == 'N/A':
                                        severity = 'High' if item.get('confidence_score', 0) >= 90 or str(item.get('port')) in ['22', '3389'] else 'Medium'
                                    
                                    findings.append({
                                        "vulnerability": f"Port {item.get('port')} ({item.get('service', 'Unknown')})",
                                        "severity": severity,
                                        "details": f"State: {item.get('state')}, Product: {item.get('product', 'N/A')}, Version: {item.get('version', 'N/A')}",
                                        "cve": item.get('cve', 'None Identified'),
                                        "remediation": item.get('remediation', 'Standard hardening recommended.'),
                                        "triage_status": item.get('triage_status', 'Unverified')
                                    })
                            else:
                                findings.append({
                                    "vulnerability": "General Scan Findings",
                                    "severity": "Medium",
                                    "details": str(analyzed_report),
                                    "cve": "N/A",
                                    "remediation": "N/A",
                                    "triage_status": "Unverified"
                                })

                            scan_entry = {
                                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "target": target,
                                "initiated_by": operator_name,
                                "findings": findings
                            }
                            scan_history.insert(0, scan_entry)
                            save_scans(scan_history)

                            active_scans_db[task_id].update({"status": "Scan Completed Successfully", "progress": "100%"})
                            await asyncio.sleep(1.5)
                            active_scans_db.pop(task_id, None)

                            process_queue_item()

                        except Exception as e:
                            logger.error(f"Task {task_id} error: {e}")
                            active_scans_db.pop(task_id, None)
                            process_queue_item()

                    def process_queue_item():
                        if scan_queue and len(active_scans_db) < 2:
                            next_item = scan_queue.pop(0)
                            tid = next_item['task_id']
                            active_scans_db[tid] = {
                                'name': next_item['name'],
                                'status': 'Queued -> Starting...',
                                'progress': '0%',
                                'task_id': tid,
                                'operator': next_item['operator']
                            }
                            task = asyncio.create_task(run_background_scan(tid, next_item['target'], next_item['ports'], next_item['operator']))
                            task_references[tid] = task

                    def trigger_scan():
                        target, selected_ports = target_input.value.strip(), ports_input.value.strip()
                        if not target or not selected_ports:
                            ui.notify('Enter target and port scope.', type='negative')
                            return
                        
                        task_id = datetime.now().strftime('%H%M%S_%f')
                        scan_name = f"Port Scan [{selected_ports}] [{target}]"

                        if len(active_scans_db) >= 2:
                            scan_queue.append({
                                'task_id': task_id,
                                'name': scan_name,
                                'target': target,
                                'ports': selected_ports,
                                'operator': current_user
                            })
                            ui.notify('Workers busy. Scan added to queue.', type='info')
                        else:
                            active_scans_db[task_id] = {
                                'name': scan_name,
                                'status': 'Initializing...',
                                'progress': '0%',
                                'task_id': task_id,
                                'operator': current_user
                            }
                            task = asyncio.create_task(run_background_scan(task_id, target, selected_ports, current_user))
                            task_references[task_id] = task
                            ui.notify(f'Scan dispatched for {target}', type='info')
                        
                        refresh_tables()

                    def cancel_scan(task_id):
                        if task_id in task_references:
                            task_references[task_id].cancel()
                            active_scans_db.pop(task_id, None)
                            ui.notify('Scan cancelled.', type='warning')
                            refresh_tables()
                            process_queue_item()

                    def cancel_queued_scan(task_id):
                        global scan_queue
                        scan_queue = [q for q in scan_queue if q['task_id'] != task_id]
                        ui.notify('Scan removed from queue.', type='warning')
                        refresh_tables()

                    def refresh_tables():
                        active_scans_container.clear()
                        with active_scans_container:
                            if active_scans_db:
                                for tid, data in list(active_scans_db.items()):
                                    with ui.row().classes('w-full justify-between items-center bg-gray-800 p-3 rounded border border-gray-700'):
                                        ui.label(f"{data['name']} (Operator: {data.get('operator','N/A')}) - [{data['status']}] ({data['progress']})").classes('font-mono text-xs text-gray-200')
                                        ui.button('Cancel', on_click=lambda t=tid: cancel_scan(t)).classes('bg-red-600 hover:bg-red-700 text-white text-xs font-mono')
                            else:
                                ui.label('No active background scan workers.').classes('text-gray-500 font-mono text-xs')

                        if is_admin:
                            queue_container.clear()
                            with queue_container:
                                if scan_queue:
                                    for idx, qitem in enumerate(scan_queue):
                                        with ui.row().classes('w-full justify-between items-center bg-gray-800 p-3 rounded border border-gray-700'):
                                            ui.label(f"#{idx+1}: {qitem['name']} (Operator: {qitem['operator']})").classes('font-mono text-xs text-yellow-300')
                                            ui.button('Remove', on_click=lambda t=qitem['task_id']: cancel_queued_scan(t)).classes('bg-yellow-700 hover:bg-yellow-800 text-white text-xs font-mono')
                                else:
                                    ui.label('Scan queue is currently empty.').classes('text-gray-500 font-mono text-xs')

                    ui.button('Start Scan / Enqueue', on_click=trigger_scan).classes('bg-red-600 hover:bg-red-700 text-white font-mono mb-4 text-xs')
                    ui.timer(1.0, refresh_tables)
                    
                    ui.label('Active Workers Execution Pipeline').classes('font-mono font-bold text-gray-300 mb-2 text-sm mt-4')
                    refresh_tables()

                    if is_admin:
                        ui.label('Pending Scan Queue (Admin Privilege)').classes('font-mono font-bold text-yellow-400 mb-2 text-sm mt-6')

    except Exception as e:
        logger.error(f"Scan management error: {e}")
        ui.label("Scan page failed").classes('text-red-500')

# ---------------- Reports (Upgraded with Granular Per-Report Exports & Disclaimer) ----------------
@ui.page('/reports')
def scan_reports():
    if check_app_status():
        return ui.run_javascript('window.location.href = "/locked"')

    try:
        user_session = get_session_user()
        if not user_session.get("authenticated"):
            return ui.run_javascript('window.location.href = "/login"')

        current_user = user_session.get("username")
        if current_user not in active_sessions:
            active_sessions.add(current_user)

        is_admin = is_master_admin(user_session)
        visible_scans = scan_history if is_admin else [s for s in scan_history if s.get('initiated_by') == current_user]

        with ui.row().classes('w-full h-screen no-wrap bg-gray-950'):
            create_sidebar()
            with ui.column().classes('flex-grow p-8 text-white overflow-y-auto'):
                with ui.row().classes('w-full justify-between items-center mb-6'):
                    ui.label('💼 Scan Results, CVE Intelligence & Triage').classes('text-2xl font-mono font-bold')
                    ui.label('Expand any specific scan entry below to export its clean triaged report.').classes('text-xs font-mono text-gray-400')

                if not visible_scans:
                    with ui.card().classes('w-full p-8 bg-gray-900 border border-gray-800 text-center'):
                        ui.label('No scan records found in your scope. Run a scan to populate reports.').classes('text-gray-400 font-mono')
                else:
                    for scan in visible_scans:
                        header_title = (
                            f"Target: {scan.get('target')}  |  Operator: {scan.get('initiated_by')}  |  Time: {scan.get('timestamp')}"
                            if is_admin else
                            f"Target: {scan.get('target')}  |  Time: {scan.get('timestamp')}"
                        )

                        with ui.expansion(header_title).classes('w-full bg-gray-900 border border-gray-800 rounded mb-4 font-mono text-white text-xs').props('dark header-class="bg-gray-900 text-white font-mono text-xs"'):
                            with ui.column().classes('w-full p-3 gap-3 bg-gray-950'):
                                
                                # --- Granular Export Toolbar for THIS Specific Report ---
                                with ui.row().classes('w-full justify-between items-center bg-gray-900 p-3 rounded border border-gray-800 mb-2'):
                                    ui.label('Export Single Report:').classes('font-mono text-xs text-blue-400 font-bold')
                                    
                                    def export_single_json(s_data=scan):
                                        export_data = json.dumps(s_data, indent=4)
                                        ui.download(export_data.encode('utf-8'), filename=f"aegis_report_{s_data.get('target','target').replace('.','_')}_{s_data.get('timestamp','').replace(':','_').replace(' ','_')}.json")
                                        ui.notify("Single report exported as JSON successfully", type='positive')

                                    def export_single_csv(s_data=scan):
                                        csv_lines = ["Timestamp,Target,Operator,Vulnerability,Severity,CVE,Remediation,TriageStatus,Details"]
                                        for f in s_data.get('findings', []):
                                            csv_lines.append(f"\"{s_data.get('timestamp','')}\",\"{s_data.get('target','')}\",\"{s_data.get('initiated_by','')}\",\"{f.get('vulnerability','')}\",\"{f.get('severity','')}\",\"{f.get('cve','')}\",\"{f.get('remediation','')}\",\"{f.get('triage_status','Unverified')}\",\"{f.get('details','')}\"")
                                        export_data = "\n".join(csv_lines)
                                        ui.download(export_data.encode('utf-8'), filename=f"aegis_report_{s_data.get('target','target').replace('.','_')}_{s_data.get('timestamp','').replace(':','_').replace(' ','_')}.csv")
                                        ui.notify("Single report exported as CSV successfully", type='positive')

                                    def export_single_txt(s_data=scan):
                                        txt_lines = [
                                            "==========================================",
                                            "         AEGIS SINGLE VAPT REPORT         ",
                                            "==========================================",
                                            f"Timestamp: {s_data.get('timestamp')}",
                                            f"Target:    {s_data.get('target')}",
                                            f"Operator:  {s_data.get('initiated_by')}",
                                            "Findings:"
                                        ]
                                        for f in s_data.get('findings', []):
                                            txt_lines.append(f"  - [{f.get('severity','Low')}] {f.get('vulnerability','N/A')} | CVE: {f.get('cve','N/A')} | Status: {f.get('triage_status','Unverified')}")
                                            txt_lines.append(f"    Details: {f.get('details','')}")
                                            txt_lines.append(f"    Remediation: {f.get('remediation','')}")
                                        txt_lines.append("-" * 42)
                                        txt_lines.append("AEGIS VAPT ENGINE - DISCLAIMER")
                                        txt_lines.append("1. Point-in-Time: Findings reflect system state at the time of testing only; new vulnerabilities may emerge continuously.")
                                        txt_lines.append("2. No Warranty: This report provides technical documentation only and offers no guarantees or warranties regarding future security or protection against breaches.")
                                        txt_lines.append("3. Remediation & Compliance: Remediation steps are recommendations only. System owners retain full responsibility for implementation, risk acceptance, and regulatory compliance.")
                                        txt_lines.append("==========================================")
                                        export_data = "\n".join(txt_lines)
                                        ui.download(export_data.encode('utf-8'), filename=f"aegis_report_{s_data.get('target','target').replace('.','_')}_{s_data.get('timestamp','').replace(':','_').replace(' ','_')}.txt")
                                        ui.notify("Single report exported as Text successfully", type='positive')

                                    with ui.row().classes('gap-2'):
                                            ui.button('Export JSON', on_click=export_single_json).classes('bg-gray-800 hover:bg-gray-700 text-[11px] font-mono text-white')
                                            ui.button('Export CSV', on_click=export_single_csv).classes('bg-gray-800 hover:bg-gray-700 text-[11px] font-mono text-white')
                                            ui.button('Export TXT', on_click=export_single_txt).classes('bg-gray-800 hover:bg-gray-700 text-[11px] font-mono text-white')

                                for finding in scan.get('findings', []):
                                    severity = finding.get('severity', 'Low')
                                    badge_color = (
                                        'bg-red-950 text-red-400 border-red-800' if severity in ['High', 'Critical'] else
                                        'bg-yellow-950 text-yellow-400 border-yellow-800' if severity == 'Medium' else
                                        'bg-green-950 text-green-400 border-green-800'
                                    )
                                    
                                    with ui.card().classes('w-full bg-gray-900 p-4 border border-gray-800'):
                                        with ui.row().classes('w-full justify-between items-center mb-2'):
                                            ui.label(finding.get('vulnerability', 'Port Check')).classes('font-mono font-bold text-sm text-white')
                                            with ui.row().classes('gap-2 items-center'):
                                                ui.label(f"CVE: {finding.get('cve', 'None')}").classes('font-mono text-xs px-2 py-1 bg-gray-800 text-blue-400 rounded border border-gray-700')
                                                ui.label(severity).classes(f'font-mono text-xs px-3 py-1 rounded border {badge_color}')

                                        ui.label(finding.get('details', '')).classes('font-mono text-xs text-gray-300 mb-2')
                                        ui.label(f"Remediation: {finding.get('remediation', 'N/A')}").classes('font-mono text-[11px] text-gray-400 mb-3 italic')

                                        with ui.row().classes('w-full justify-between items-center bg-gray-950 p-2 rounded border border-gray-800'):
                                            ui.label('Manual Triage Status:').classes('font-mono text-xs text-gray-400')
                                            
                                            def update_triage_state(f_ref, new_status):
                                                f_ref['triage_status'] = new_status
                                                save_scans(scan_history)
                                                ui.notify(f"Finding marked as {new_status}", type='positive')

                                            ui.select(
                                                options=['Unverified', 'Verified True Positive', 'False Positive', 'Reported'],
                                                value=finding.get('triage_status', 'Unverified'),
                                                on_change=lambda e, f=finding: update_triage_state(f, e.value)
                                            ).classes('w-56 text-white').props('dark outlined dense')

                                # --- Integrated Disclaimer Footer Box ---
                                with ui.card().classes('w-full bg-gray-900/60 p-3 border border-gray-800 mt-2'):
                                    ui.label('--- AEGIS VAPT ENGINE - DISCLAIMER ---').classes('font-mono text-[11px] text-yellow-500 font-bold mb-1')
                                    ui.label('1. Point-in-Time: Findings reflect system state at the time of testing only; new vulnerabilities may emerge continuously.').classes('font-mono text-[10px] text-gray-400')
                                    ui.label('2. No Warranty: This report provides technical documentation only and offers no guarantees or warranties regarding future security or protection against breaches.').classes('font-mono text-[10px] text-gray-400')
                                    ui.label('3. Remediation & Compliance: Remediation steps are recommendations only. System owners retain full responsibility for implementation, risk acceptance, and regulatory compliance.').classes('font-mono text-[10px] text-gray-400')

    except Exception as e:
        logger.error(f"Reports page error: {e}")
        ui.label("Reports page failed").classes('text-red-500')

# ---------------- Admin Dashboard ----------------
@ui.page('/admin')
def admin_settings():
    if check_app_status():
        return ui.run_javascript('window.location.href = "/locked"')

    try:
        user_session = get_session_user()
        if not user_session.get("authenticated"):
            return ui.run_javascript('window.location.href = "/login"')

        with ui.row().classes('w-full h-screen no-wrap bg-gray-950'):
            create_sidebar()
            with ui.column().classes('flex-grow p-8 text-white overflow-y-auto'):
                ui.label('💻 Admin Security Controls & Command Center').classes('text-2xl font-mono font-bold mb-2')
                ui.label('Select a module below to manage platform security, queues, and operators.').classes('text-xs font-mono text-gray-400 mb-8')
                
                if not is_master_admin(user_session):
                    with ui.card().classes('w-full p-8 bg-red-950 border border-red-800 text-center'):
                        ui.label('ACCESS RESTRICTED').classes('text-xl font-mono font-bold text-red-400 mb-2')
                        ui.label('Only administrator accounts are authorized to access security controls.').classes('text-sm text-gray-300 font-mono')
                else:
                    display_area = ui.column().classes('w-full mt-4')

                    def render_killswitch_view():
                        display_area.clear()
                        with display_area:
                            with ui.card().classes('p-6 w-full bg-gray-900 border border-red-900'):
                                ui.label('🚨 Global System Kill Switch').classes('font-mono font-bold text-red-400 mb-2 text-sm')
                                ui.label('Instantly lock down and disable the entire application platform for all users.').classes('text-xs text-gray-400 mb-4')

                                def toggle_disable_app():
                                    cfg = load_system_config()
                                    cfg["app_disabled"] = True
                                    save_system_config(cfg)
                                    ui.notify('Platform disabled successfully via Kill Switch.', type='negative')
                                    ui.run_javascript('window.location.href = "/locked"')

                                ui.button('Activate Global Kill Switch', on_click=toggle_disable_app).classes('bg-red-600 hover:bg-red-700 text-white font-mono text-xs')

                    def render_operators_view():
                        display_area.clear()
                        with display_area:
                            with ui.card().classes('p-6 w-full bg-gray-900 border border-gray-800'):
                                ui.label('👥 Active Operators & Engagement Status').classes('font-mono font-bold text-blue-400 mb-2 text-sm')
                                ui.label('Displays operators with active authenticated sessions. Logged-out users are automatically omitted.').classes('text-xs text-gray-400 mb-4')

                                active_users_container = ui.column().classes('w-full gap-3')

                                def refresh_active_operators():
                                    global registered_users
                                    registered_users = load_users()
                                    active_users_container.clear()
                                    
                                    engaged_operators = set()
                                    for scan_data in active_scans_db.values():
                                        if 'operator' in scan_data:
                                            engaged_operators.add(scan_data['operator'])
                                    for q_item in scan_queue:
                                        if 'operator' in q_item:
                                            engaged_operators.add(q_item['operator'])

                                    with active_users_container:
                                        active_found = False
                                        for uname in list(active_sessions):
                                            if uname in registered_users:
                                                info = registered_users[uname]
                                                if info.get('status', 'Active') == 'Active':
                                                    active_found = True
                                                    is_engaged = uname in engaged_operators
                                                    status_badge = '🔥 Engaged (Running Scan)' if is_engaged else '🟢 Active Session'
                                                    badge_color = 'text-red-400 border-red-800 bg-red-950' if is_engaged else 'text-green-400 border-green-800 bg-green-950'

                                                    with ui.row().classes('w-full justify-between items-center bg-gray-800 p-3 rounded border border-gray-700'):
                                                        ui.label(f"{uname} ({info.get('role', 'Analyst')})").classes('font-mono text-sm text-white font-bold')
                                                        ui.label(status_badge).classes(f'font-mono text-xs px-3 py-1 rounded border {badge_color}')
                                        if not active_found:
                                            ui.label('No active operators currently logged in.').classes('text-gray-500 font-mono text-xs')

                                refresh_active_operators()
                                ui.timer(2.0, refresh_active_operators)

                    def render_queue_view():
                        display_area.clear()
                        with display_area:
                            with ui.card().classes('p-6 w-full bg-gray-900 border border-gray-800'):
                                ui.label('📡 Live Scan Queue Monitor').classes('font-mono font-bold text-yellow-400 mb-2 text-sm')
                                admin_queue_container = ui.column().classes('w-full gap-2')

                                def refresh_admin_queue():
                                    admin_queue_container.clear()
                                    with admin_queue_container:
                                        if scan_queue:
                                            for idx, q in enumerate(scan_queue):
                                                with ui.row().classes('w-full justify-between items-center bg-gray-800 p-2 rounded border border-gray-700'):
                                                    ui.label(f"Position #{idx+1} | Target: {q['target']} | Operator: {q['operator']} | Scope: {q['ports']}").classes('font-mono text-xs text-yellow-300')
                                        else:
                                            ui.label('Queue is currently empty.').classes('text-gray-500 font-mono text-xs')

                                refresh_admin_queue()
                                ui.timer(1.0, refresh_admin_queue)

                    def render_permissions_view():
                        display_area.clear()
                        with display_area:
                            with ui.card().classes('p-6 w-full bg-gray-900 border border-gray-800'):
                                ui.label('⚙️ Operator Deactivation & Permission Management').classes('font-mono font-bold text-gray-200 mb-4 text-sm')
                                users_container = ui.column().classes('w-full gap-3')

                                def update_role(uname, new_role):
                                    global registered_users
                                    registered_users = load_users()
                                    if uname in registered_users:
                                        registered_users[uname]["role"] = new_role
                                        save_users(registered_users)
                                        ui.notify(f"Updated {uname} role to {new_role}", type='positive')

                                def toggle_user_status(uname):
                                    global registered_users
                                    registered_users = load_users()
                                    if uname in registered_users:
                                        current_status = registered_users[uname].get("status", "Active")
                                        new_status = "Deactivated" if current_status == "Active" else "Active"
                                        registered_users[uname]["status"] = new_status
                                        save_users(registered_users)
                                        if new_status == 'Deactivated' and uname in active_sessions:
                                            active_sessions.remove(uname)
                                        ui.notify(f"User {uname} status changed to {new_status}", type='warning' if new_status == 'Deactivated' else 'positive')
                                        render_users_list()

                                def render_users_list():
                                    global registered_users
                                    registered_users = load_users()
                                    users_container.clear()
                                    with users_container:
                                        for uname, info in registered_users.items():
                                            with ui.row().classes('w-full justify-between items-center bg-gray-800 p-3 rounded border border-gray-700'):
                                                with ui.row().classes('items-center gap-4'):
                                                    ui.label(uname).classes('font-mono text-sm text-white font-bold')
                                                    status = info.get('status', 'Active')
                                                    status_color = 'text-green-400 border-green-800 bg-green-950' if status == 'Active' else 'text-red-400 border-red-800 bg-red-950'
                                                    ui.label(status).classes(f'font-mono text-xs px-2 py-0.5 rounded border {status_color}')

                                                with ui.row().classes('gap-2 items-center'):
                                                    ui.select(
                                                        options=['Administrator', 'Analyst'],
                                                        value=info.get('role', 'Analyst'),
                                                        on_change=lambda e, u=uname: update_role(u, e.value)
                                                    ).classes('w-40 text-white').props('dark outlined')
                                                    
                                                    action_label = "Deactivate" if info.get('status', 'Active') == "Active" else "Activate"
                                                    btn_color = 'bg-yellow-700 hover:bg-yellow-800' if action_label == 'Deactivate' else 'bg-green-700 hover:bg-green-800'
                                                    ui.button(action_label, on_click=lambda u=uname: toggle_user_status(u)).classes(f'{btn_color} text-white text-xs font-mono')

                                render_users_list()

                    with ui.row().classes('w-full gap-4 mb-6'):
                        with ui.card().classes('cursor-pointer p-5 bg-gray-900 hover:bg-gray-800 border border-red-900/50 hover:border-red-600 flex-grow text-center items-center rounded transition-all').on('click', render_killswitch_view):
                            ui.label('🚨').classes('text-2xl mb-1')
                            ui.label('Kill Switch').classes('font-mono text-xs font-bold text-red-400')

                        with ui.card().classes('cursor-pointer p-5 bg-gray-900 hover:bg-gray-800 border border-blue-900/50 hover:border-blue-600 flex-grow text-center items-center rounded transition-all').on('click', render_operators_view):
                            ui.label('👥').classes('text-2xl mb-1')
                            ui.label('Operators').classes('font-mono text-xs font-bold text-blue-400')

                        with ui.card().classes('cursor-pointer p-5 bg-gray-900 hover:bg-gray-800 border border-yellow-900/50 hover:border-yellow-600 flex-grow text-center items-center rounded transition-all').on('click', render_queue_view):
                            ui.label('📡').classes('text-2xl mb-1')
                            ui.label('Scan Queue').classes('font-mono text-xs font-bold text-yellow-400')

                        with ui.card().classes('cursor-pointer p-5 bg-gray-900 hover:bg-gray-800 border border-gray-700 hover:border-gray-500 flex-grow text-center items-center rounded transition-all').on('click', render_permissions_view):
                            ui.label('⚙️').classes('text-2xl mb-1')
                            ui.label('Permissions').classes('font-mono text-xs font-bold text-gray-200')

                    render_operators_view()

    except Exception as e:
        logger.error(f"Admin page error: {e}")
        ui.label("Admin page failed").classes('text-red-500')

ui.run_with(
    fastapi_app, 
    mount_path='/',
    storage_secret='aegis_secure_vapt_secret_key_2026'
)

if __name__ =="__main__":
    uvicorn.run(fastapi_app, host="0.0.0.0", port=8080)
