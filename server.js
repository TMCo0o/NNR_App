const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
const path = require("path");

const app = express();
app.use(express.static(path.join(__dirname, "www")));

const db = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL
        ? { rejectUnauthorized: false }
        : false
});

app.use(cors());
app.use(express.json({ limit: "1mb" }));

// =====================================================
// HELPERS
// =====================================================

function clean(value, max = 200) {
    return String(value ?? "")
        .trim()
        .slice(0, max);
}

async function getUser(id) {
    const result = await db.query(
        `SELECT * FROM users WHERE id = $1`,
        [Number(id)]
    );

    return result.rows[0] || null;
}

function userForClient(user) {
    return {
        id: user.id,
        username: user.username,
        firstName: user.first_name,
        lastName: user.last_name,
        age: user.age ?? null,
        gender: user.gender ?? "",
        balance: user.balance,
        isAdmin: Boolean(user.is_admin)
    };
}

async function addNotification(userId, title, message, kind = "info") {
    await db.query(
        `
        INSERT INTO notifications
            (user_id, title, message, kind)
        VALUES
            ($1, $2, $3, $4)
        `,
        [
            Number(userId),
            clean(title, 100),
            clean(message, 1000),
            clean(kind, 30)
        ]
    );
}

async function requireGovernment(req, res) {
    const id = Number(
        req.body.adminId ??
        req.query.adminId ??
        req.params.adminId
    );

    const user = await getUser(id);

    if (!user || !user.is_admin || user.username !== "Government") {
        res.status(403).json({
            error: "Government access required."
        });
        return null;
    }

    return user;
}

async function createTransaction(
    senderId,
    receiverId,
    amount,
    type = "transfer",
    note = ""
) {
    await db.query(
        `
        INSERT INTO transactions
            (sender_id, receiver_id, amount, type, note)
        VALUES
            ($1, $2, $3, $4, $5)
        `,
        [
            senderId ?? null,
            receiverId ?? null,
            Number(amount),
            clean(type, 30),
            clean(note, 500)
        ]
    );
}

async function withTransaction(callback) {
    const client = await db.connect();

    try {
        await client.query("BEGIN");
        const result = await callback(client);
        await client.query("COMMIT");
        return result;
    } catch (error) {
        await client.query("ROLLBACK");
        throw error;
    } finally {
        client.release();
    }
}

async function createTransactionWithClient(
    client,
    senderId,
    receiverId,
    amount,
    type = "transfer",
    note = ""
) {
    await client.query(
        `
        INSERT INTO transactions
            (sender_id, receiver_id, amount, type, note)
        VALUES
            ($1, $2, $3, $4, $5)
        `,
        [
            senderId ?? null,
            receiverId ?? null,
            Number(amount),
            clean(type, 30),
            clean(note, 500)
        ]
    );
}

async function addNotificationWithClient(
    client,
    userId,
    title,
    message,
    kind = "info"
) {
    await client.query(
        `
        INSERT INTO notifications
            (user_id, title, message, kind)
        VALUES
            ($1, $2, $3, $4)
        `,
        [
            Number(userId),
            clean(title, 100),
            clean(message, 1000),
            clean(kind, 30)
        ]
    );
}

// =====================================================
// DATABASE
// =====================================================

async function initDatabase() {
    await db.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            age INTEGER,
            gender TEXT,
            pin_hash TEXT NOT NULL,
            balance INTEGER NOT NULL DEFAULT 0,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id SERIAL PRIMARY KEY,
            sender_id INTEGER REFERENCES users(id),
            receiver_id INTEGER REFERENCES users(id),
            amount INTEGER NOT NULL,
            type TEXT NOT NULL DEFAULT 'transfer',
            note TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS notifications (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            kind TEXT NOT NULL DEFAULT 'info',
            read INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS news (
            id SERIAL PRIMARY KEY,
            organization TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ
        );

        CREATE TABLE IF NOT EXISTS elections (
            id SERIAL PRIMARY KEY,
            position TEXT NOT NULL,
            title TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS candidates (
            id SERIAL PRIMARY KEY,
            election_id INTEGER NOT NULL REFERENCES elections(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            vote_count INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS kk_requests (
            id SERIAL PRIMARY KEY,
            requester_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            target_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            amount INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        ALTER TABLE users ADD COLUMN IF NOT EXISTS age INTEGER;
        ALTER TABLE users ADD COLUMN IF NOT EXISTS gender TEXT;
        ALTER TABLE transactions ADD COLUMN IF NOT EXISTS type TEXT NOT NULL DEFAULT 'transfer';
        ALTER TABLE transactions ADD COLUMN IF NOT EXISTS note TEXT;
    `);
}

// =====================================================
// SERVER STATUS
// =====================================================

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "www", "index.html"));
});

// =====================================================
// REGISTER
// =====================================================

app.post("/api/register", async (req, res) => {
    try {
        const username = clean(req.body.username, 20);
        const firstName = clean(req.body.firstName, 50);
        const lastName = clean(req.body.lastName, 50);
        const pin = clean(req.body.pin, 6);
        const age = Number(req.body.age);
        const gender = clean(req.body.gender, 30);

        if (!username || !firstName || !lastName || !pin || !gender) {
            return res.status(400).json({
                error: "All fields are required."
            });
        }

        if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
            return res.status(400).json({
                error: "Username must be 3-20 letters, numbers, or underscores."
            });
        }

        if (!/^\d{6}$/.test(pin)) {
            return res.status(400).json({
                error: "PIN must be exactly 6 numbers."
            });
        }

        if (!Number.isInteger(age) || age < 1 || age > 120) {
            return res.status(400).json({
                error: "Enter a valid age."
            });
        }

        const existingUser = await db.query(
            `SELECT id FROM users WHERE username = $1`,
            [username]
        );

        if (existingUser.rowCount > 0) {
            return res.status(409).json({
                error: "Username already exists."
            });
        }

        const pinHash = await bcrypt.hash(pin, 12);

        const result = await db.query(
            `
            INSERT INTO users
                (username, first_name, last_name, age, gender, pin_hash)
            VALUES
                ($1, $2, $3, $4, $5, $6)
            RETURNING id
            `,
            [username, firstName, lastName, age, gender, pinHash]
        );

        res.json({
            success: true,
            userId: result.rows[0].id
        });
    } catch (error) {
        console.error(error);

        if (error.code === "23505") {
            return res.status(409).json({
                error: "Username already exists."
            });
        }

        res.status(500).json({
            error: "Registration failed."
        });
    }
});

// =====================================================
// LOGIN
// =====================================================

app.post("/api/login", async (req, res) => {
    try {
        const username = clean(req.body.username, 20);
        const pin = clean(req.body.pin, 6);

        const result = await db.query(
            `SELECT * FROM users WHERE username = $1`,
            [username]
        );

        const user = result.rows[0];

        if (!user || !(await bcrypt.compare(pin, user.pin_hash))) {
            return res.status(401).json({
                error: "Invalid username or PIN."
            });
        }

        res.json({
            success: true,
            user: userForClient(user)
        });
    } catch (error) {
        console.error(error);

        res.status(500).json({
            error: "Login failed."
        });
    }
});

// =====================================================
// USER
// =====================================================

app.get("/api/user/:userId", async (req, res) => {
    try {
        const user = await getUser(req.params.userId);

        if (!user) {
            return res.status(404).json({
                error: "Account not found."
            });
        }

        res.json({
            success: true,
            user: userForClient(user)
        });
    } catch (error) {
        console.error(error);

        res.status(500).json({
            error: "Could not load account."
        });
    }
});

// =====================================================
// CHANGE USERNAME
// =====================================================

app.post("/api/change-username", async (req, res) => {
    try {
        const userId = Number(req.body.userId);
        const username = clean(req.body.newUsername, 20);

        if (
            !Number.isInteger(userId) ||
            !/^[a-zA-Z0-9_]{3,20}$/.test(username)
        ) {
            return res.status(400).json({
                error: "Invalid username."
            });
        }

        if (!(await getUser(userId))) {
            return res.status(404).json({
                error: "Account not found."
            });
        }

        const existing = await db.query(
            `
            SELECT id
            FROM users
            WHERE username = $1
            AND id != $2
            `,
            [username, userId]
        );

        if (existing.rowCount > 0) {
            return res.status(409).json({
                error: "Username already exists."
            });
        }

        await db.query(
            `
            UPDATE users
            SET username = $1
            WHERE id = $2
            `,
            [username, userId]
        );

        res.json({
            success: true,
            username
        });
    } catch (error) {
        console.error(error);

        if (error.code === "23505") {
            return res.status(409).json({
                error: "Username already exists."
            });
        }

        res.status(500).json({
            error: "Could not change username."
        });
    }
});

// =====================================================
// KK TRANSFER
// =====================================================

app.post("/api/transfer", async (req, res) => {
    try {
        const senderId = Number(req.body.senderId);
        const receiverUsername = clean(
            req.body.receiverUsername,
            20
        );
        const amount = Number(req.body.amount);

        if (!Number.isInteger(amount) || amount <= 0) {
            return res.status(400).json({
                error: "Amount must be a positive whole number."
            });
        }

        await withTransaction(async (client) => {
            const senderResult = await client.query(
                `SELECT * FROM users WHERE id = $1 FOR UPDATE`,
                [senderId]
            );

            const sender = senderResult.rows[0];

            const receiverResult = await client.query(
                `SELECT * FROM users WHERE username = $1 FOR UPDATE`,
                [receiverUsername]
            );

            const receiver = receiverResult.rows[0];

            if (!sender || !receiver) {
                const error = new Error("Account not found.");
                error.statusCode = 404;
                throw error;
            }

            if (sender.id === receiver.id) {
                const error = new Error(
                    "You cannot send KK to yourself."
                );
                error.statusCode = 400;
                throw error;
            }

            const government =
                sender.username === "Government" &&
                Boolean(sender.is_admin);

            if (!government && amount > sender.balance) {
                const error = new Error(
                    "Insufficient KK balance."
                );
                error.statusCode = 400;
                throw error;
            }

            if (!government) {
                await client.query(
                    `
                    UPDATE users
                    SET balance = balance - $1
                    WHERE id = $2
                    `,
                    [amount, sender.id]
                );
            }

            await client.query(
                `
                UPDATE users
                SET balance = balance + $1
                WHERE id = $2
                `,
                [amount, receiver.id]
            );

            await createTransactionWithClient(
                client,
                sender.id,
                receiver.id,
                amount,
                government
                    ? "government_give"
                    : "transfer",
                government
                    ? "Government issued KK"
                    : "Member transfer"
            );

            await addNotificationWithClient(
                client,
                receiver.id,
                "KK received",
                `${sender.username} sent you ${amount.toLocaleString()} KK.`,
                "kk"
            );
        });

        const updated = await getUser(senderId);

        res.json({
            success: true,
            message:
                `Sent ${amount.toLocaleString()} KK to ${receiverUsername}.`,
            newBalance: updated.balance
        });
    } catch (error) {
        console.error(error);

        if (error.statusCode) {
            return res.status(error.statusCode).json({
                error: error.message
            });
        }

        res.status(500).json({
            error: "Transfer failed."
        });
    }
});

// =====================================================
// LAST 5 TRANSACTIONS
// =====================================================

app.get("/api/transactions/:userId", async (req, res) => {
    try {
        const userId = Number(req.params.userId);

        if (!(await getUser(userId))) {
            return res.status(404).json({
                error: "Account not found."
            });
        }

        const result = await db.query(
            `
            SELECT
                t.*,
                s.username AS sender_username,
                r.username AS receiver_username
            FROM transactions t
            LEFT JOIN users s
                ON s.id = t.sender_id
            LEFT JOIN users r
                ON r.id = t.receiver_id
            WHERE
                t.sender_id = $1
                OR t.receiver_id = $1
            ORDER BY t.id DESC
            LIMIT 5
            `,
            [userId]
        );

        res.json({
            success: true,
            transactions: result.rows
        });
    } catch (error) {
        console.error(error);

        res.status(500).json({
            error: "Could not load transactions."
        });
    }
});

// =====================================================
// REQUEST KK
// =====================================================

app.post("/api/kk/request", async (req, res) => {
    try {
        const requesterId = Number(req.body.requesterId);
        const targetUsername = clean(
            req.body.targetUsername,
            20
        );
        const amount = Number(req.body.amount);

        const requester = await getUser(requesterId);

        const targetResult = await db.query(
            `SELECT * FROM users WHERE username = $1`,
            [targetUsername]
        );

        const target = targetResult.rows[0];

        if (!requester || !target) {
            return res.status(404).json({
                error: "Account not found."
            });
        }

        if (requester.id === target.id) {
            return res.status(400).json({
                error: "You cannot request KK from yourself."
            });
        }

        if (!Number.isInteger(amount) || amount <= 0) {
            return res.status(400).json({
                error: "Amount must be a positive whole number."
            });
        }

        const result = await db.query(
            `
            INSERT INTO kk_requests
                (requester_id, target_id, amount)
            VALUES
                ($1, $2, $3)
            RETURNING id
            `,
            [requester.id, target.id, amount]
        );

        await addNotification(
            target.id,
            "KK request",
            `@${requester.username} requested ${amount.toLocaleString()} KK from you.`,
            "kk_request"
        );

        res.json({
            success: true,
            requestId: result.rows[0].id
        });
    } catch (error) {
        console.error(error);

        res.status(500).json({
            error: "Could not create KK request."
        });
    }
});

// =====================================================
// PENDING KK REQUESTS
// =====================================================

app.get("/api/kk/requests/:userId", async (req, res) => {
    try {
        const userId = Number(req.params.userId);

        const result = await db.query(
            `
            SELECT
                r.*,
                u.username AS requester_username
            FROM kk_requests r
            JOIN users u
                ON u.id = r.requester_id
            WHERE
                r.target_id = $1
                AND r.status = 'pending'
            ORDER BY r.id DESC
            `,
            [userId]
        );

        res.json({
            success: true,
            requests: result.rows
        });
    } catch (error) {
        console.error(error);

        res.status(500).json({
            error: "Could not load KK requests."
        });
    }
});

// =====================================================
// ACCEPT / DENY KK REQUEST
// =====================================================

app.post("/api/kk/request/:id/respond", async (req, res) => {
    try {
        const requestId = Number(req.params.id);
        const userId = Number(req.body.userId);
        const action = clean(req.body.action, 20).toLowerCase();

        if (!["accept", "deny"].includes(action)) {
            return res.status(400).json({
                error: "Invalid request action."
            });
        }

        await withTransaction(async (client) => {
            const requestResult = await client.query(
                `
                SELECT *
                FROM kk_requests
                WHERE id = $1
                FOR UPDATE
                `,
                [requestId]
            );

            const request = requestResult.rows[0];

            if (!request) {
                const error = new Error(
                    "KK request not found."
                );
                error.statusCode = 404;
                throw error;
            }

            if (Number(request.target_id) !== userId) {
                const error = new Error(
                    "You cannot respond to this request."
                );
                error.statusCode = 403;
                throw error;
            }

            if (request.status !== "pending") {
                const error = new Error(
                    "This request has already been answered."
                );
                error.statusCode = 400;
                throw error;
            }

            if (action === "deny") {
                await client.query(
                    `
                    UPDATE kk_requests
                    SET status = 'denied'
                    WHERE id = $1
                    `,
                    [requestId]
                );

                await addNotificationWithClient(
                    client,
                    request.requester_id,
                    "KK request denied",
                    `Your request for ${Number(request.amount).toLocaleString()} KK was denied.`,
                    "kk_request"
                );

                return;
            }

            const targetResult = await client.query(
                `
                SELECT *
                FROM users
                WHERE id = $1
                FOR UPDATE
                `,
                [request.target_id]
            );

            const target = targetResult.rows[0];

            if (!target) {
                const error = new Error(
                    "Account not found."
                );
                error.statusCode = 404;
                throw error;
            }

            if (Number(target.balance) < Number(request.amount)) {
                const error = new Error(
                    "You do not have enough KK."
                );
                error.statusCode = 400;
                throw error;
            }

            await client.query(
                `
                UPDATE users
                SET balance = balance - $1
                WHERE id = $2
                `,
                [request.amount, target.id]
            );

            await client.query(
                `
                UPDATE users
                SET balance = balance + $1
                WHERE id = $2
                `,
                [request.amount, request.requester_id]
            );

            await client.query(
                `
                UPDATE kk_requests
                SET status = 'accepted'
                WHERE id = $1
                `,
                [requestId]
            );

            await createTransactionWithClient(
                client,
                target.id,
                request.requester_id,
                request.amount,
                "transfer",
                "KK request accepted"
            );

            const requesterResult = await client.query(
                `
                SELECT username
                FROM users
                WHERE id = $1
                `,
                [request.requester_id]
            );

            const requester = requesterResult.rows[0];

            await addNotificationWithClient(
                client,
                request.requester_id,
                "KK request accepted",
                `Your request was accepted and ${Number(request.amount).toLocaleString()} KK was sent to you.`,
                "kk_request"
            );

            if (requester) {
                await addNotificationWithClient(
                    client,
                    target.id,
                    "KK sent",
                    `You sent ${Number(request.amount).toLocaleString()} KK to @${requester.username}.`,
                    "kk"
                );
            }
        });

        res.json({
            success: true
        });
    } catch (error) {
        console.error(error);

        if (error.statusCode) {
            return res.status(error.statusCode).json({
                error: error.message
            });
        }

        res.status(500).json({
            error: "Could not respond to KK request."
        });
    }
});

// =====================================================
// NOTIFICATIONS
// =====================================================

app.get("/api/notifications/:userId", async (req, res) => {
    try {
        const userId = Number(req.params.userId);

        const result = await db.query(
            `
            SELECT *
            FROM notifications
            WHERE user_id = $1
            ORDER BY id DESC
            LIMIT 30
            `,
            [userId]
        );

        res.json({
            success: true,
            notifications: result.rows
        });
    } catch (error) {
        console.error(error);

        res.status(500).json({
            error: "Could not load notifications."
        });
    }
});

// =====================================================
// MARK NOTIFICATIONS READ
// =====================================================

app.post("/api/notifications/read", async (req, res) => {
    try {
        const userId = Number(req.body.userId);

        await db.query(
            `
            UPDATE notifications
            SET read = 1
            WHERE user_id = $1
            `,
            [userId]
        );

        res.json({
            success: true
        });
    } catch (error) {
        console.error(error);

        res.status(500).json({
            error: "Could not mark notifications as read."
        });
    }
});

// =====================================================
// NEWS — EVERYONE CAN READ
// =====================================================

app.get("/api/news", async (req, res) => {
    try {
        const result = await db.query(
            `
            SELECT *
            FROM news
            ORDER BY id DESC
            `
        );

        res.json({
            success: true,
            news: result.rows
        });
    } catch (error) {
        console.error(error);

        res.status(500).json({
            error: "Could not load news."
        });
    }
});

// =====================================================
// GOVERNMENT — CREATE NEWS
// =====================================================

app.post("/api/admin/news", async (req, res) => {
    try {
        const admin = await requireGovernment(req, res);

        if (!admin) return;

        const organization = clean(
            req.body.organization,
            80
        );

        const title = clean(
            req.body.title,
            200
        );

        const content = clean(
            req.body.content,
            5000
        );

        if (!organization || !title || !content) {
            return res.status(400).json({
                error:
                    "Organization, title, and content are required."
            });
        }

        const result = await db.query(
            `
            INSERT INTO news
                (organization, title, content)
            VALUES
                ($1, $2, $3)
            RETURNING id
            `,
            [organization, title, content]
        );

        res.json({
            success: true,
            id: result.rows[0].id
        });
    } catch (error) {
        console.error(error);

        res.status(500).json({
            error: "Could not create news."
        });
    }
});

// =====================================================
// GOVERNMENT — EDIT NEWS
// =====================================================

app.put("/api/admin/news/:id", async (req, res) => {
    try {
        const admin = await requireGovernment(req, res);

        if (!admin) return;

        const id = Number(req.params.id);

        const organization = clean(
            req.body.organization,
            80
        );

        const title = clean(
            req.body.title,
            200
        );

        const content = clean(
            req.body.content,
            5000
        );

        if (!organization || !title || !content) {
            return res.status(400).json({
                error:
                    "Organization, title, and content are required."
            });
        }

        await db.query(
            `
            UPDATE news
            SET
                organization = $1,
                title = $2,
                content = $3,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = $4
            `,
            [
                organization,
                title,
                content,
                id
            ]
        );

        res.json({
            success: true
        });
    } catch (error) {
        console.error(error);

        res.status(500).json({
            error: "Could not edit news."
        });
    }
});
// =====================================================
// GOVERNMENT — DELETE NEWS
// =====================================================

app.delete("/api/admin/news/:id", async (req, res) => {
    try {
        const admin = await requireGovernment(req, res);

        if (!admin) return;

        await db.query(
            `
            DELETE FROM news
            WHERE id = $1
            `,
            [Number(req.params.id)]
        );

        res.json({
            success: true
        });
    } catch (error) {
        console.error(error);

        res.status(500).json({
            error: "Could not delete news."
        });
    }
});

// =====================================================
// ELECTIONS — EVERYONE CAN READ
// =====================================================

app.get("/api/elections", async (req, res) => {
    try {
        const electionsResult = await db.query(
            `
            SELECT *
            FROM elections
            ORDER BY id DESC
            `
        );

        const elections = electionsResult.rows;

        for (const election of elections) {
            const candidatesResult = await db.query(
                `
                SELECT
                    id,
                    name,
                    vote_count
                FROM candidates
                WHERE election_id = $1
                ORDER BY
                    vote_count DESC,
                    name ASC
                `,
                [election.id]
            );

            election.candidates = candidatesResult.rows;
        }

        res.json({
            success: true,
            elections
        });
    } catch (error) {
        console.error(error);

        res.status(500).json({
            error: "Could not load elections."
        });
    }
});

// =====================================================
// GOVERNMENT — CREATE ELECTION
// =====================================================

app.post("/api/admin/elections", async (req, res) => {
    try {
        const admin = await requireGovernment(req, res);

        if (!admin) return;

        const position = clean(
            req.body.position,
            100
        );

        const title = clean(
            req.body.title,
            150
        );

        const candidates = Array.isArray(
            req.body.candidates
        )
            ? req.body.candidates
            : [];

        if (!position || !title || !candidates.length) {
            return res.status(400).json({
                error:
                    "Position, title, and at least one candidate are required."
            });
        }

        const electionId = await withTransaction(
            async (client) => {
                const electionResult = await client.query(
                    `
                    INSERT INTO elections
                        (position, title, active)
                    VALUES
                        ($1, $2, 1)
                    RETURNING id
                    `,
                    [position, title]
                );

                const id = electionResult.rows[0].id;

                for (const candidate of candidates) {
                    const name = clean(
                        candidate.name,
                        100
                    );

                    if (!name) continue;

                    const voteCount = Math.max(
                        0,
                        Number(candidate.voteCount) || 0
                    );

                    await client.query(
                        `
                        INSERT INTO candidates
                            (election_id, name, vote_count)
                        VALUES
                            ($1, $2, $3)
                        `,
                        [
                            id,
                            name,
                            voteCount
                        ]
                    );
                }

                return id;
            }
        );

        res.json({
            success: true,
            id: electionId
        });
    } catch (error) {
        console.error(error);

        res.status(500).json({
            error: "Could not create election."
        });
    }
});

// =====================================================
// GOVERNMENT — EDIT ELECTION
// =====================================================

app.put("/api/admin/elections/:id", async (req, res) => {
    try {
        const admin = await requireGovernment(req, res);

        if (!admin) return;

        const electionId = Number(
            req.params.id
        );

        const position = clean(
            req.body.position,
            100
        );

        const title = clean(
            req.body.title,
            150
        );

        const active = req.body.active ? 1 : 0;

        const candidates = Array.isArray(
            req.body.candidates
        )
            ? req.body.candidates
            : [];

        if (!position || !title) {
            return res.status(400).json({
                error:
                    "Position and title are required."
            });
        }

        await withTransaction(async (client) => {
            await client.query(
                `
                UPDATE elections
                SET
                    position = $1,
                    title = $2,
                    active = $3
                WHERE id = $4
                `,
                [
                    position,
                    title,
                    active,
                    electionId
                ]
            );

            await client.query(
                `
                DELETE FROM candidates
                WHERE election_id = $1
                `,
                [electionId]
            );

            for (const candidate of candidates) {
                const name = clean(
                    candidate.name,
                    100
                );

                if (!name) continue;

                const voteCount = Math.max(
                    0,
                    Number(candidate.voteCount) || 0
                );

                await client.query(
                    `
                    INSERT INTO candidates
                        (election_id, name, vote_count)
                    VALUES
                        ($1, $2, $3)
                    `,
                    [
                        electionId,
                        name,
                        voteCount
                    ]
                );
            }
        });

        res.json({
            success: true
        });
    } catch (error) {
        console.error(error);

        res.status(500).json({
            error: "Could not edit election."
        });
    }
});

// =====================================================
// GOVERNMENT — DELETE ELECTION
// =====================================================

app.delete("/api/admin/elections/:id", async (req, res) => {
    try {
        const admin = await requireGovernment(req, res);

        if (!admin) return;

        await db.query(
            `
            DELETE FROM elections
            WHERE id = $1
            `,
            [Number(req.params.id)]
        );

        res.json({
            success: true
        });
    } catch (error) {
        console.error(error);

        res.status(500).json({
            error: "Could not delete election."
        });
    }
});

// =====================================================
// GOVERNMENT — VIEW ALL MEMBERS
// =====================================================

app.get("/api/admin/members", async (req, res) => {
    try {
        const adminId = Number(
            req.query.adminId
        );

        const admin = await getUser(adminId);

        if (
            !admin ||
            !admin.is_admin ||
            admin.username !== "Government"
        ) {
            return res.status(403).json({
                error: "Government access required."
            });
        }

        const result = await db.query(
            `
            SELECT
                id,
                username,
                first_name,
                last_name,
                age,
                gender,
                balance,
                is_admin,
                created_at
            FROM users
            ORDER BY LOWER(username) ASC
            `
        );

        res.json({
            success: true,
            members: result.rows.map(
                userForClient
            )
        });
    } catch (error) {
        console.error(error);

        res.status(500).json({
            error: "Could not load members."
        });
    }
});

// =====================================================
// GOVERNMENT — GIVE KK
// =====================================================

app.post("/api/admin/kk/give", async (req, res) => {
    try {
        const admin = await requireGovernment(req, res);

        if (!admin) return;

        const username = clean(
            req.body.username,
            20
        );

        const amount = Number(
            req.body.amount
        );

        if (!Number.isInteger(amount) || amount <= 0) {
            return res.status(400).json({
                error: "Invalid amount."
            });
        }

        await withTransaction(async (client) => {
            const result = await client.query(
                `
                SELECT *
                FROM users
                WHERE username = $1
                FOR UPDATE
                `,
                [username]
            );

            const target = result.rows[0];

            if (!target) {
                const error = new Error(
                    "Account not found."
                );
                error.statusCode = 404;
                throw error;
            }

            await client.query(
                `
                UPDATE users
                SET balance = balance + $1
                WHERE id = $2
                `,
                [
                    amount,
                    target.id
                ]
            );

            await createTransactionWithClient(
                client,
                null,
                target.id,
                amount,
                "government_give",
                "Government gave KK"
            );

            await addNotificationWithClient(
                client,
                target.id,
                "KK received",
                `Government gave you ${amount.toLocaleString()} KK.`,
                "kk"
            );
        });

        res.json({
            success: true
        });
    } catch (error) {
        console.error(error);

        if (error.statusCode) {
            return res.status(error.statusCode).json({
                error: error.message
            });
        }

        res.status(500).json({
            error: "Could not give KK."
        });
    }
});

// =====================================================
// GOVERNMENT — TAKE KK
// =====================================================

app.post("/api/admin/kk/take", async (req, res) => {
    try {
        const admin = await requireGovernment(req, res);

        if (!admin) return;

        const username = clean(
            req.body.username,
            20
        );

        const amount = Number(
            req.body.amount
        );

        if (!Number.isInteger(amount) || amount <= 0) {
            return res.status(400).json({
                error: "Invalid amount."
            });
        }

        await withTransaction(async (client) => {
            const result = await client.query(
                `
                SELECT *
                FROM users
                WHERE username = $1
                FOR UPDATE
                `,
                [username]
            );

            const target = result.rows[0];

            if (!target) {
                const error = new Error(
                    "Account not found."
                );
                error.statusCode = 404;
                throw error;
            }

            if (Number(target.balance) < amount) {
                const error = new Error(
                    "That account does not have enough KK."
                );
                error.statusCode = 400;
                throw error;
            }

            await client.query(
                `
                UPDATE users
                SET balance = balance - $1
                WHERE id = $2
                `,
                [
                    amount,
                    target.id
                ]
            );

            await createTransactionWithClient(
                client,
                target.id,
                null,
                amount,
                "government_take",
                "Government took KK"
            );

            await addNotificationWithClient(
                client,
                target.id,
                "KK removed",
                `Government removed ${amount.toLocaleString()} KK from your account.`,
                "kk"
            );
        });

        res.json({
            success: true
        });
    } catch (error) {
        console.error(error);

        if (error.statusCode) {
            return res.status(error.statusCode).json({
                error: error.message
            });
        }

        res.status(500).json({
            error: "Could not take KK."
        });
    }
});

// =====================================================
// GOVERNMENT — SEND NOTIFICATION
// =====================================================

app.post("/api/admin/notify", async (req, res) => {
    try {
        const admin = await requireGovernment(req, res);

        if (!admin) return;

        const title =
            clean(req.body.title, 100) ||
            "NNR Notification";

        const message = clean(
            req.body.message,
            1000
        );

        const targetUsername = clean(
            req.body.targetUsername ||
            req.body.username,
            20
        );

        const broadcast =
            Boolean(req.body.broadcast);

        if (!message) {
            return res.status(400).json({
                error:
                    "Notification message is required."
            });
        }

        // Send to one person.
        if (targetUsername && !broadcast) {
            const result = await db.query(
                `
                SELECT id
                FROM users
                WHERE username = $1
                `,
                [targetUsername]
            );

            const target = result.rows[0];

            if (!target) {
                return res.status(404).json({
                    error: "Account not found."
                });
            }

            await addNotification(
                target.id,
                title,
                message,
                "government"
            );

            return res.json({
                success: true,
                sent: 1
            });
        }

        // Broadcast to everybody.
        const result = await db.query(
            `SELECT id FROM users`
        );

        await withTransaction(async (client) => {
            for (const user of result.rows) {
                await addNotificationWithClient(
                    client,
                    user.id,
                    title,
                    message,
                    "government"
                );
            }
        });

        res.json({
            success: true,
            sent: result.rows.length
        });
    } catch (error) {
        console.error(error);

        res.status(500).json({
            error:
                "Could not send notification."
        });
    }
});

// =====================================================
// START SERVER
// =====================================================

const PORT = Number(
    process.env.PORT || 3000
);

async function startServer() {
    try {
        await initDatabase();

        console.log(
            "PostgreSQL database initialized."
        );

        app.listen(
            PORT,
            "0.0.0.0",
            () => {
                console.log(
                    `NNR Server running on port ${PORT}`
                );
            }
        );
    } catch (error) {
        console.error(
            "Failed to initialize NNR server:",
            error
        );

        process.exit(1);
    }
}

startServer();

