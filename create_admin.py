!from project import create_app, db
from project.models import User

def create_admin():
    """Creates an admin user."""
    app = create_app()
    with app.app_context():
        email = input("Enter admin email: ")
        password = input("Enter admin password: ")

        user = User.query.filter_by(email=email).first()
        if user:
            print(f"User with email {email} already exists.")
            user.role = 'admin'
            db.session.commit()
            print("User role updated to admin.")
        else:
            new_user = User(
                email=email,
                name="Admin",
                role='admin'
            )
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            print(f"Admin user {email} created successfully.")

if __name__ == "__main__":
    create_admin()

