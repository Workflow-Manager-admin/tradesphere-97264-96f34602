import os
import sqlite3
from fastapi import FastAPI, APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict
from datetime import datetime, timedelta
from jose import JWTError, jwt


# Settings
DB_PATH = os.environ.get("SQLITE_DB", "quantico.sqlite")
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "supersecret")  # In prod: use secure key!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# FastAPI app
app = FastAPI(
    title="Quantico Backend API",
    description=(
        "API for Quantico: trading strategy builder, backtesting, paper trading, "
        "portfolio and AI assistant."
    ),
    version="0.1.0",
    openapi_tags=[
        {"name": "Authentication", "description": "User login, registration, password reset, OAuth"},
        {"name": "Strategies", "description": "CRUD for trading strategies and indicators"},
        {"name": "Market Data", "description": "Fetching live/historic market data"},
        {"name": "Backtesting", "description": "Backtest engine endpoints"},
        {"name": "Paper Trading", "description": "Simulated trading and logs"},
        {"name": "Portfolio", "description": "Portfolio and performance tracking"},
        {"name": "AI Assistant", "description": "AI queries and suggestions"},
        {"name": "WebSocket", "description": "Real-time event updates"},
        {"name": "Health", "description": "Health and status endpoints"},
    ],
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")


# ========== DATABASE UTILS =========================================


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS strategies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT NOT NULL,
            description TEXT,
            json_body TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS backtests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            strategy_id INTEGER,
            status TEXT,
            result_json TEXT,
            started_at TEXT,
            completed_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (strategy_id) REFERENCES strategies(id)
        );
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS trades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            strategy_id INTEGER,
            symbol TEXT,
            side TEXT,
            qty REAL,
            price REAL,
            executed_at TEXT,
            paper BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (strategy_id) REFERENCES strategies(id)
        );
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS ai_queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            query TEXT,
            response TEXT,
            created_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        """)
        conn.commit()


init_db()


# ========== UTILS / AUTH HELPERS =========================


def fake_hash_password(password: str):
    # In real world, use passlib or bcrypt
    return "fakehashed$" + password


def verify_password(plain_password, hashed_password):
    # In real world, use passlib.verify
    return hashed_password == fake_hash_password(plain_password)


def create_access_token(data: dict, expires_delta: timedelta = None):
    """Create JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_user_by_email(conn, email: str):
    cur = conn.execute("SELECT * FROM users WHERE email=?", (email,))
    row = cur.fetchone()
    return dict(row) if row else None


def get_user(conn, user_id: int):
    cur = conn.execute("SELECT * FROM users WHERE id=?", (user_id,))
    row = cur.fetchone()
    return dict(row) if row else None


def authenticate_user(conn, email: str, password: str):
    user = get_user_by_email(conn, email)
    if user and verify_password(password, user["hashed_password"]):
        return user
    return None


# PUBLIC_INTERFACE
async def get_current_user(
    token: str = Depends(oauth2_scheme), db=Depends(get_db)
):
    """Validate JWT token and extract user."""
    credentials_exception = HTTPException(
        status_code=401, detail="Could not validate credentials"
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(db, user_id)
    if user is None:
        raise credentials_exception
    return user


# ========== SCHEMAS ================================


# AUTH SCHEMAS
class UserCreate(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: int
    email: EmailStr
    created_at: str


class Token(BaseModel):
    access_token: str
    token_type: str


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    email: EmailStr
    new_password: str


# STRATEGY
class StrategyBase(BaseModel):
    name: str
    description: Optional[str] = None
    json_body: dict


class StrategyCreate(StrategyBase):
    pass


class StrategyOut(StrategyBase):
    id: int
    created_at: str
    updated_at: str


# BACKTEST AND TRADES
class BacktestCreate(BaseModel):
    strategy_id: int


class BacktestOut(BaseModel):
    id: int
    status: str
    result_json: Optional[dict] = None
    started_at: str
    completed_at: Optional[str] = None


class TradeOut(BaseModel):
    id: int
    symbol: str
    side: str
    qty: float
    price: float
    executed_at: str
    paper: bool


# PORTFOLIO
class PortfolioOut(BaseModel):
    equity: float
    pnl: float
    open_positions: List[dict]


# AI
class AIQueryRequest(BaseModel):
    query: str


class AIQueryResponse(BaseModel):
    response: str


# ========== ROUTERS ==================================

router = APIRouter()

# ----------- AUTHENTICATION ----------------------------------------
@router.post("/auth/signup", response_model=UserOut, tags=["Authentication"])
def signup(user: UserCreate, db=Depends(get_db)):
    """
    PUBLIC_INTERFACE
    Register a new user with email and password.
    """
    cur = db.execute("SELECT * FROM users WHERE email=?", (user.email,))
    if cur.fetchone():
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = fake_hash_password(user.password)
    created_at = datetime.utcnow().isoformat()
    db.execute(
        "INSERT INTO users (email, hashed_password, created_at) VALUES (?, ?, ?)",
        (user.email, hashed, created_at),
    )
    db.commit()
    db_user = get_user_by_email(db, user.email)
    return UserOut(**db_user)


@router.post("/auth/token", response_model=Token, tags=["Authentication"])
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), db=Depends(get_db)
):
    """
    PUBLIC_INTERFACE
    Obtain a JWT access token via login with email and password.
    """
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": user["id"]})
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/auth/password-reset", tags=["Authentication"])
def request_password_reset(req: PasswordResetRequest, db=Depends(get_db)):
    """
    PUBLIC_INTERFACE
    Request password reset, initiating the process (normally via email).
    """
    # For demo: just check user exists
    user = get_user_by_email(db, req.email)
    if not user:
        raise HTTPException(status_code=404, detail="No such user")
    return {"message": "Check your email for reset instructions."}


@router.post("/auth/password-reset/confirm", tags=["Authentication"])
def confirm_password_reset(req: PasswordResetConfirm, db=Depends(get_db)):
    """
    PUBLIC_INTERFACE
    Confirm new password for password reset flow.
    """
    user = get_user_by_email(db, req.email)
    if not user:
        raise HTTPException(status_code=404, detail="No such user")
    db.execute(
        "UPDATE users SET hashed_password=? WHERE email=?",
        (fake_hash_password(req.new_password), req.email),
    )
    db.commit()
    return {"message": "Password updated successfully."}


# Google OAuth2 mock endpoint for demo (skipped real OAuth flow for brevity)
@router.post("/auth/google", tags=["Authentication"])
def login_google(token: str = Body(...), db=Depends(get_db)):
    """
    PUBLIC_INTERFACE
    Google OAuth login mock. Accepts Google token and registers/logs in.
    """
    # Here you would validate token with Google.
    email = "user_google@example.com"
    user = get_user_by_email(db, email)
    if not user:
        now = datetime.utcnow().isoformat()
        db.execute(
            "INSERT INTO users (email, hashed_password, created_at) VALUES (?, ?, ?)",
            (email, fake_hash_password("dummy"), now),
        )
        db.commit()
        user = get_user_by_email(db, email)
    access_token = create_access_token(data={"sub": user["id"]})
    return {"access_token": access_token, "token_type": "bearer"}


# ----------- STRATEGY BUILDER MANAGEMENT ---------------------------
@router.post("/strategies", response_model=StrategyOut, tags=["Strategies"])
def create_strategy(
    s: StrategyCreate, user=Depends(get_current_user), db=Depends(get_db)
):
    """
    PUBLIC_INTERFACE
    Add a new trading strategy.
    """
    now = datetime.utcnow().isoformat()
    cur = db.execute(
        """
        INSERT INTO strategies (user_id, name, description, json_body, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            user["id"],
            s.name,
            s.description or "",
            str(s.json_body),
            now,
            now,
        ),
    )
    db.commit()
    strategy_id = cur.lastrowid
    row = db.execute("SELECT * FROM strategies WHERE id=?", (strategy_id,)).fetchone()
    return StrategyOut(
        id=row["id"],
        name=row["name"],
        description=row["description"],
        json_body=eval(row["json_body"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


@router.get("/strategies", response_model=List[StrategyOut], tags=["Strategies"])
def list_strategies(user=Depends(get_current_user), db=Depends(get_db)):
    """
    PUBLIC_INTERFACE
    List all strategies for current user.
    """
    cur = db.execute("SELECT * FROM strategies WHERE user_id=?", (user["id"],))
    rows = cur.fetchall()
    return [
        StrategyOut(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            json_body=eval(row["json_body"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
        for row in rows
    ]


@router.get("/strategies/{strategy_id}", response_model=StrategyOut, tags=["Strategies"])
def get_strategy(strategy_id: int, user=Depends(get_current_user), db=Depends(get_db)):
    """
    PUBLIC_INTERFACE
    Retrieve a trading strategy by ID.
    """
    row = db.execute(
        "SELECT * FROM strategies WHERE id=? AND user_id=?",
        (strategy_id, user["id"]),
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    return StrategyOut(
        id=row["id"],
        name=row["name"],
        description=row["description"],
        json_body=eval(row["json_body"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


@router.put("/strategies/{strategy_id}", response_model=StrategyOut, tags=["Strategies"])
def update_strategy(
    strategy_id: int, s: StrategyCreate, user=Depends(get_current_user), db=Depends(get_db)
):
    """
    PUBLIC_INTERFACE
    Update an existing trading strategy.
    """
    now = datetime.utcnow().isoformat()
    db.execute(
        """
        UPDATE strategies SET name=?, description=?, json_body=?, updated_at=?
        WHERE id=? AND user_id=?
        """,
        (s.name, s.description or "", str(s.json_body), now, strategy_id, user["id"]),
    )
    db.commit()
    row = db.execute("SELECT * FROM strategies WHERE id=?", (strategy_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    return StrategyOut(
        id=row["id"],
        name=row["name"],
        description=row["description"],
        json_body=eval(row["json_body"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


@router.delete("/strategies/{strategy_id}", tags=["Strategies"])
def delete_strategy(strategy_id: int, user=Depends(get_current_user), db=Depends(get_db)):
    """
    PUBLIC_INTERFACE
    Delete a trading strategy by ID.
    """
    db.execute(
        "DELETE FROM strategies WHERE id=? AND user_id=?", (strategy_id, user["id"])
    )
    db.commit()
    return {"ok": True}


# ----------- MARKET DATA FETCHING ----------------------------------
@router.get("/market-data", tags=["Market Data"])
def get_market_data(symbol: str, interval: str = "1d"):
    """
    PUBLIC_INTERFACE
    Fetch simulated market data (demo stub).
    """
    # In prod: connect to a market data provider (eg, Yahoo, Binance, AlphaVantage, etc)
    data = [
        {"ts": "2024-06-01", "open": 100, "high": 105, "low": 98, "close": 103, "volume": 1000},
        {"ts": "2024-06-02", "open": 103, "high": 107, "low": 102, "close": 104, "volume": 1500},
        {"ts": "2024-06-03", "open": 104, "high": 108, "low": 101, "close": 107, "volume": 2000},
    ]
    return {"symbol": symbol, "interval": interval, "data": data}


# ----------- BACKTEST EXECUTION ------------------------------------
@router.post("/backtests", response_model=BacktestOut, tags=["Backtesting"])
def run_backtest(
    req: BacktestCreate, user=Depends(get_current_user), db=Depends(get_db)
):
    """
    PUBLIC_INTERFACE
    Run a backtest on an existing strategy (stub logic).
    """
    now = datetime.utcnow().isoformat()
    strategy = db.execute(
        "SELECT * FROM strategies WHERE id=? AND user_id=?", (req.strategy_id, user["id"])
    ).fetchone()
    if not strategy:
        raise HTTPException(status_code=404, detail="Strategy not found")
    # Simulate a backtest
    backtest_status = "completed"
    result_json = {"result": "success", "pnl": 1234.5}
    db.execute(
        """
        INSERT INTO backtests (user_id, strategy_id, status, result_json, started_at, completed_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            user["id"],
            req.strategy_id,
            backtest_status,
            str(result_json),
            now,
            now,
        ),
    )
    db.commit()
    row = db.execute(
        "SELECT * FROM backtests WHERE user_id=? ORDER BY id DESC LIMIT 1", (user["id"],)
    ).fetchone()
    return BacktestOut(
        id=row["id"],
        status=row["status"],
        result_json=eval(row["result_json"]),
        started_at=row["started_at"],
        completed_at=row["completed_at"],
    )


@router.get("/backtests", response_model=List[BacktestOut], tags=["Backtesting"])
def get_backtest_results(user=Depends(get_current_user), db=Depends(get_db)):
    """
    PUBLIC_INTERFACE
    List all backtest results for the current user.
    """
    cur = db.execute("SELECT * FROM backtests WHERE user_id=?", (user["id"],))
    rows = cur.fetchall()
    return [
        BacktestOut(
            id=row["id"],
            status=row["status"],
            result_json=eval(row["result_json"]) if row["result_json"] else None,
            started_at=row["started_at"],
            completed_at=row["completed_at"],
        )
        for row in rows
    ]


# ----------- PAPER TRADING -----------------------------------------
@router.post("/paper-trade", tags=["Paper Trading"])
def execute_paper_trade(
    symbol: str,
    side: str,
    qty: float,
    price: float,
    strategy_id: int,
    user=Depends(get_current_user),
    db=Depends(get_db),
):
    """
    PUBLIC_INTERFACE
    Simulate a paper trade.
    """
    executed_at = datetime.utcnow().isoformat()
    db.execute(
        """
        INSERT INTO trades (user_id, strategy_id, symbol, side, qty, price, executed_at, paper)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1)
        """,
        (user["id"], strategy_id, symbol, side, qty, price, executed_at),
    )
    db.commit()
    trade_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    row = db.execute("SELECT * FROM trades WHERE id=?", (trade_id,)).fetchone()
    return {
        "id": row["id"],
        "symbol": row["symbol"],
        "side": row["side"],
        "qty": row["qty"],
        "price": row["price"],
        "executed_at": row["executed_at"],
        "paper": True,
    }


@router.get("/paper-trades", response_model=List[TradeOut], tags=["Paper Trading"])
def get_paper_trades(
    strategy_id: Optional[int] = None,
    user=Depends(get_current_user),
    db=Depends(get_db),
):
    """
    PUBLIC_INTERFACE
    List paper trades.
    """
    q = "SELECT * FROM trades WHERE user_id=? AND paper=1"
    params = [user["id"]]
    if strategy_id:
        q += " AND strategy_id=?"
        params.append(strategy_id)
    cur = db.execute(q, tuple(params))
    rows = cur.fetchall()
    return [
        TradeOut(
            id=row["id"],
            symbol=row["symbol"],
            side=row["side"],
            qty=row["qty"],
            price=row["price"],
            executed_at=row["executed_at"],
            paper=True,
        )
        for row in rows
    ]


# ----------- PORTFOLIO TRACKING ------------------------------------
@router.get("/portfolio", response_model=PortfolioOut, tags=["Portfolio"])
def get_portfolio(user=Depends(get_current_user), db=Depends(get_db)):
    """
    PUBLIC_INTERFACE
    Return a summary of the user's portfolio.
    """
    # Demo stub logic
    equity = 100_000
    pnl = 1234.5
    open_positions = [{"symbol": "AAPL", "qty": 50, "price": 202}]
    return PortfolioOut(equity=equity, pnl=pnl, open_positions=open_positions)


# ----------- AI ASSISTANT ------------------------------------------
@router.post("/ai/query", response_model=AIQueryResponse, tags=["AI Assistant"])
def ask_ai(req: AIQueryRequest, user=Depends(get_current_user), db=Depends(get_db)):
    """
    PUBLIC_INTERFACE
    Query the AI assistant for strategy suggestion or explanation (mock).
    """
    # Demo response; in prod send to OpenAI/LLM backend
    response = f"AI suggestion for: {req.query}"
    now = datetime.utcnow().isoformat()
    db.execute(
        "INSERT INTO ai_queries (user_id, query, response, created_at) VALUES (?, ?, ?, ?)",
        (user["id"], req.query, response, now),
    )
    db.commit()
    return AIQueryResponse(response=response)


# ----------- BROKER API STUB ---------------------------------------
@router.get("/broker/status", tags=["Portfolio"])
def broker_status(user=Depends(get_current_user)):
    """
    PUBLIC_INTERFACE
    Return mock status of external broker connection for the user.
    """
    return {"connected": False, "msg": "No broker linked (demo stub)"}


# ----------- HEALTH CHECK ENDPOINTS --------------------------------
@router.get("/health/db", tags=["Health"])
def health_db():
    """
    PUBLIC_INTERFACE
    Check health (connectivity) of the SQLite DB.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("SELECT 1")
        conn.close()
        return {"status": "ok", "detail": "DB connection successful"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB error: {e}")


@router.get("/health", tags=["Health"])
def health():
    """
    PUBLIC_INTERFACE
    Basic health check.
    """
    return {"status": "ok"}


# ----------- REAL TIME UPDATES VIA WEBSOCKETS ----------------------
class WebSocketManager:
    def __init__(self):
        self.active_connections: Dict[int, List[WebSocket]] = {}

    # PUBLIC_INTERFACE
    async def connect(self, user_id: int, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.setdefault(user_id, []).append(websocket)

    # PUBLIC_INTERFACE
    def disconnect(self, user_id: int, websocket: WebSocket):
        if user_id in self.active_connections:
            try:
                self.active_connections[user_id].remove(websocket)
            except ValueError:
                pass

    # PUBLIC_INTERFACE
    async def send_personal_message(self, user_id: int, message: str):
        for ws in self.active_connections.get(user_id, []):
            await ws.send_text(message)

    # PUBLIC_INTERFACE
    async def broadcast(self, message: str):
        for user_id, ws_list in self.active_connections.items():
            for ws in ws_list:
                await ws.send_text(message)


manager = WebSocketManager()


@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: int):
    """
    PUBLIC_INTERFACE

    WebSocket endpoint for real-time updates.
    - operationId: websocket_real_time_user_updates
    """
    await manager.connect(user_id, websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Echo message or process events here
            await manager.send_personal_message(user_id, f"You wrote: {data}")
    except WebSocketDisconnect:
        manager.disconnect(user_id, websocket)


# ========== REGISTER ROUTER ==========
app.include_router(router)


# ========== DOCS ROUTE FOR WEBSOCKET USAGE =============
@app.get("/docs/ws", tags=["WebSocket"])
def websocket_usage():
    """
    PUBLIC_INTERFACE

    Returns notes on WebSocket URL and usage for clients.
    """
    return {
        "websocket_url": "/ws/{user_id}",
        "description": (
            "Connect with JWT-authenticated user's id for real-time updates. "
            "See event type docs for application-specific messages."
        ),
    }


# ========== LANDING PAGE (optionally secured) ===============
@app.get("/", tags=["Health"])
def landing():
    """PUBLIC_INTERFACE
    Simple API root.
    """
    return {"message": "Healthy"}
