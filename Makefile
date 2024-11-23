local_run:
	poetry install
	poetry run python src/main.py

create_db:
	poetry run python create_db.py

migrate_db_head:
	poetry run alembic -c "src/alembic/alembic.ini" upgrade head

lint_and_format:
	poetry run black src --check .
	poetry run flake8