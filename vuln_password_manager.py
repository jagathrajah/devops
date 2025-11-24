def _setup_master_if_missing():
    master = load_master_password()
    if not master:
        print("No master password set. Setting up now.")
        pw = input("Set master password: ")
        store_master_password(pw)
        print("Master password stored (insecure).")
        return pw
    return master

def _authenticate_master(stored_master) -> bool:
    m = input("Enter master password: ")
    if m != stored_master:
        print("Invalid master password!")
        return False
    return True

def _handle_add():
    site = input("Site: ")
    user = input("Username: ")
    pwd = input("Password: ")
    add_password(site, user, pwd)

def _handle_list():
    site = input("Site (or % for all): ")
    results = get_passwords_for_site(site)
    for r in results:
        print(r)

def _handle_gen():
    try:
        l = input("Length: ")
        l = int(l) if l.strip() else 8
    except ValueError:
        l = 8
    print("Generated:", generate_password(l))

def _handle_export():
    fn = input("Export filename: ")
    export_vault(fn)

def _handle_shell():
    cmdline = input("Shell command to run: ")
    print(run_shell_command(cmdline))

def _handle_eval(cmd):
    try:
        print(eval(cmd))
    except Exception:
        # intentionally swallowing errors to preserve original behavior
        pass

def interactive():
    """Refactored interactive loop — uses helper handlers and a dispatch table
    to reduce cognitive complexity while keeping original insecure behaviors."""
    init_db()
    print("=== Vulnerable Password Manager (SAST demo) ===")

    stored_master = _setup_master_if_missing()
    # If setup created the master, stored_master is the new password string.
    # If load returned None (shouldn't after setup), try loading again:
    if stored_master is None:
        stored_master = load_master_password()

    # If a master exists (either loaded or just created), authenticate
    if stored_master:
        if not _authenticate_master(stored_master):
            return

    handlers = {
        "add": _handle_add,
        "list": _handle_list,
        "gen": _handle_gen,
        "export": _handle_export,
        "shell": _handle_shell,
        "quit": None,  # special-cased below
    }

    while True:
        print("\nOptions: add, list, gen, export, shell, quit")
        cmd = input("> ").strip()

        if cmd == "quit":
            break

        if cmd in handlers and handlers[cmd] is not None:
            try:
                handlers[cmd]()
            except Exception:
                # keep behavior tolerant like original (do not crash on handler errors)
                pass
            continue

        # fallback: attempt to evaluate user input (preserve original unsafe behavior)
        _handle_eval(cmd)
