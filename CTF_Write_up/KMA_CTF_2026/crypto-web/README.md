# Crypto Web Challenge

Register an account, start a login session, then submit the registration
receipt fields to the verifier.

## Run

```bash
docker compose up --build
```

The container waits for a debugger on `127.0.0.1:5678`. In VS Code, use
`Attach Docker debugpy`, then open `http://127.0.0.1:5000`.

or:

```bash
pip install -r requirements.txt
python -m backend.main
```

For local debugging in VS Code, use `Run Flask locally`.
