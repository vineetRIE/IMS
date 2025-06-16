from models.user import db, Machine

def init_machines():
    """Initialize machines RGI-96-1 to RGI-96-10."""
    print("Starting machine initialization...")
    machine_names = [f'RGI-96-{i}' for i in range(1, 11)]
    existing_machines = Machine.query.filter(Machine.name.in_(machine_names)).all()
    existing_names = {m.name for m in existing_machines}

    count_added = 0
    for name in machine_names:
        if name not in existing_names:
            try:
                machine = Machine(name=name)
                db.session.add(machine)
                db.session.flush()
                print(f"Added machine: {name}")
                count_added += 1
            except Exception as e:
                print(f"Error adding machine {name}: {str(e)}")
        else:
            print(f"Machine already exists: {name}")

    try:
        db.session.commit()
        print(f"Machine initialization completed: {count_added} machines added.")
    except Exception as e:
        db.session.rollback()
        print(f"Machine initialization error: {str(e)}")
        raise e