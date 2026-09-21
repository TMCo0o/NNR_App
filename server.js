const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const Database = require("better-sqlite3");

const app = express();
const db = new Database("nnr.db");

app.use(cors());
app.use(express.json({ limit: "1mb" }));

// =====================================================
// DATABASE
// =====================================================

db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    age INTEGER,
    gender TEXT,
    pin_hash TEXT NOT NULL,
    balance INTEGER NOT NULL DEFAULT 0,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER,
    receiver_id INTEGER,
    amount INTEGER NOT NULL,
    type TEXT NOT NULL DEFAULT 'transfer',
    note TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(sender_id)
        REFERENCES users(id),

    FOREIGN KEY(receiver_id)
        REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'info',
    read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS news (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS elections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    position TEXT NOT NULL,
    title TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    election_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    vote_count INTEGER NOT NULL DEFAULT 0,

    FOREIGN KEY(election_id)
        REFERENCES elections(id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS kk_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requester_id INTEGER NOT NULL,
    target_id INTEGER NOT NULL,
    amount INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(requester_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    FOREIGN KEY(target_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);
`);

// =====================================================
// OLD DATABASE MIGRATIONS
// =====================================================

for (const statement of [
    `ALTER TABLE users ADD COLUMN age INTEGER`,
    `ALTER TABLE users ADD COLUMN gender TEXT`,
    `ALTER TABLE transactions ADD COLUMN type TEXT NOT NULL DEFAULT 'transfer'`,
    `ALTER TABLE transactions ADD COLUMN note TEXT`
]) {
    try {
        db.exec(statement);
    } catch (_) {
        // Column already exists.
    }
}

// =====================================================
// HELPERS
// =====================================================

function clean(value, max = 200) {
    return String(value ?? "")
        .trim()
        .slice(0, max);
}

function getUser(id) {
    return db
        .prepare(`
            SELECT *
            FROM users
            WHERE id = ?
        `)
        .get(Number(id));
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

function addNotification(
    userId,
    title,
    message,
    kind = "info"
) {
    db.prepare(`
        INSERT INTO notifications
        (
            user_id,
            title,
            message,
            kind
        )
        VALUES (?, ?, ?, ?)
    `).run(
        userId,
        clean(title, 100),
        clean(message, 1000),
        clean(kind, 30)
    );
}

function requireGovernment(req, res) {
    const id = Number(
        req.body.adminId ??
        req.query.adminId ??
        req.params.adminId
    );

    const user = getUser(id);

    if (
        !user ||
        !user.is_admin ||
        user.username !== "Government"
    ) {
        res.status(403).json({
            error: "Government access required."
        });

        return null;
    }

    return user;
}

function createTransaction(
    senderId,
    receiverId,
    amount,
    type = "transfer",
    note = ""
) {
    db.prepare(`
        INSERT INTO transactions
        (
            sender_id,
            receiver_id,
            amount,
            type,
            note
        )
        VALUES (?, ?, ?, ?, ?)
    `).run(
        senderId ?? null,
        receiverId ?? null,
        amount,
        type,
        note
    );
}

// =====================================================
// SERVER STATUS
// =====================================================

app.get("/", (req, res) => {
    res.json({
        name: "NNR Server",
        status: "online"
    });
});

// =====================================================
// REGISTER
// =====================================================

app.post("/api/register", async (req, res) => {
    try {
        const username =
            clean(req.body.username, 20);

        const firstName =
            clean(req.body.firstName, 50);

        const lastName =
            clean(req.body.lastName, 50);

        const pin =
            clean(req.body.pin, 6);

        const age =
            Number(req.body.age);

        const gender =
            clean(req.body.gender, 30);

        if (
            !username ||
            !firstName ||
            !lastName ||
            !pin ||
            !gender
        ) {
            return res.status(400).json({
                error: "All fields are required."
            });
        }

        if (
            !/^[a-zA-Z0-9_]{3,20}$/.test(username)
        ) {
            return res.status(400).json({
                error:
                    "Username must be 3-20 letters, numbers, or underscores."
            });
        }

        if (!/^\d{6}$/.test(pin)) {
            return res.status(400).json({
                error:
                    "PIN must be exactly 6 numbers."
            });
        }

        if (
            !Number.isInteger(age) ||
            age < 1 ||
            age > 120
        ) {
            return res.status(400).json({
                error:
                    "Enter a valid age."
            });
        }

        const existingUser =
            db.prepare(`
                SELECT id
                FROM users
                WHERE username = ?
            `).get(username);

        if (existingUser) {
            return res.status(409).json({
                error:
                    "Username already exists."
            });
        }

        const pinHash =
            await bcrypt.hash(pin, 12);

        const result =
            db.prepare(`
                INSERT INTO users
                (
                    username,
                    first_name,
                    last_name,
                    age,
                    gender,
                    pin_hash
                )
                VALUES (?, ?, ?, ?, ?, ?)
            `).run(
                username,
                firstName,
                lastName,
                age,
                gender,
                pinHash
            );

        res.json({
            success: true,
            userId: result.lastInsertRowid
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            error:
                "Registration failed."
        });
    }
});

// =====================================================
// LOGIN
// =====================================================

app.post("/api/login", async (req, res) => {
    try {
        const username =
            clean(req.body.username, 20);

        const pin =
            clean(req.body.pin, 6);

        const user =
            db.prepare(`
                SELECT *
                FROM users
                WHERE username = ?
            `).get(username);

        if (
            !user ||
            !(await bcrypt.compare(
                pin,
                user.pin_hash
            ))
        ) {
            return res.status(401).json({
                error:
                    "Invalid username or PIN."
            });
        }

        res.json({
            success: true,
            user: userForClient(user)
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            error:
                "Login failed."
        });
    }
});

// =====================================================
// USER
// =====================================================

app.get("/api/user/:userId", (req, res) => {
    const user =
        getUser(req.params.userId);

    if (!user) {
        return res.status(404).json({
            error:
                "Account not found."
        });
    }

    res.json({
        success: true,
        user: userForClient(user)
    });
});

// =====================================================
// CHANGE USERNAME
// =====================================================

app.post("/api/change-username", (req, res) => {
    const userId =
        Number(req.body.userId);

    const username =
        clean(req.body.newUsername, 20);

    if (
        !Number.isInteger(userId) ||
        !/^[a-zA-Z0-9_]{3,20}$/.test(
            username
        )
    ) {
        return res.status(400).json({
            error:
                "Invalid username."
        });
    }

    if (!getUser(userId)) {
        return res.status(404).json({
            error:
                "Account not found."
        });
    }

    const existing =
        db.prepare(`
            SELECT id
            FROM users
            WHERE username = ?
            AND id != ?
        `).get(
            username,
            userId
        );

    if (existing) {
        return res.status(409).json({
            error:
                "Username already exists."
        });
    }

    db.prepare(`
        UPDATE users
        SET username = ?
        WHERE id = ?
    `).run(
        username,
        userId
    );

    res.json({
        success: true,
        username
    });
});

// =====================================================
// KK TRANSFER
// =====================================================

app.post("/api/transfer", (req, res) => {
    try {
        const senderId =
            Number(req.body.senderId);

        const receiverUsername =
            clean(
                req.body.receiverUsername,
                20
            );

        const amount =
            Number(req.body.amount);

        const sender =
            getUser(senderId);

        const receiver =
            db.prepare(`
                SELECT *
                FROM users
                WHERE username = ?
            `).get(
                receiverUsername
            );

        if (!sender || !receiver) {
            return res.status(404).json({
                error:
                    "Account not found."
            });
        }

        if (
            !Number.isInteger(amount) ||
            amount <= 0
        ) {
            return res.status(400).json({
                error:
                    "Amount must be a positive whole number."
            });
        }

        if (sender.id === receiver.id) {
            return res.status(400).json({
                error:
                    "You cannot send KK to yourself."
            });
        }

        const government =
            sender.username === "Government" &&
            sender.is_admin;

        if (
            !government &&
            amount > sender.balance
        ) {
            return res.status(400).json({
                error:
                    "Insufficient KK balance."
            });
        }

        db.transaction(() => {

            if (!government) {
                db.prepare(`
                    UPDATE users
                    SET balance = balance - ?
                    WHERE id = ?
                `).run(
                    amount,
                    sender.id
                );
            }

            db.prepare(`
                UPDATE users
                SET balance = balance + ?
                WHERE id = ?
            `).run(
                amount,
                receiver.id
            );

            createTransaction(
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

            addNotification(
                receiver.id,
                "KK received",
                `${sender.username} sent you ${amount.toLocaleString()} KK.`,
                "kk"
            );
        })();

        const updated =
            getUser(sender.id);

        res.json({
            success: true,

            message:
                `Sent ${amount.toLocaleString()} KK to ${receiver.username}.`,

            newBalance:
                updated.balance
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            error:
                "Transfer failed."
        });
    }
});

// =====================================================
// LAST 5 TRANSACTIONS
// =====================================================

app.get(
    "/api/transactions/:userId",
    (req, res) => {

        const userId =
            Number(req.params.userId);

        if (!getUser(userId)) {
            return res.status(404).json({
                error:
                    "Account not found."
            });
        }

        const transactions =
            db.prepare(`
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
                    t.sender_id = ?
                    OR
                    t.receiver_id = ?

                ORDER BY t.id DESC

                LIMIT 5
            `).all(
                userId,
                userId
            );

        res.json({
            success: true,
            transactions
        });
    }
);

// =====================================================
// REQUEST KK
// =====================================================

app.post(
    "/api/kk/request",
    (req, res) => {

        const requesterId =
            Number(req.body.requesterId);

        const targetUsername =
            clean(
                req.body.targetUsername,
                20
            );

        const amount =
            Number(req.body.amount);

        const requester =
            getUser(requesterId);

        const target =
            db.prepare(`
                SELECT *
                FROM users
                WHERE username = ?
            `).get(
                targetUsername
            );

        if (!requester || !target) {
            return res.status(404).json({
                error:
                    "Account not found."
            });
        }

        if (
            requester.id === target.id
        ) {
            return res.status(400).json({
                error:
                    "You cannot request KK from yourself."
            });
        }

        if (
            !Number.isInteger(amount) ||
            amount <= 0
        ) {
            return res.status(400).json({
                error:
                    "Amount must be a positive whole number."
            });
        }

        const result =
            db.prepare(`
                INSERT INTO kk_requests
                (
                    requester_id,
                    target_id,
                    amount
                )
                VALUES (?, ?, ?)
            `).run(
                requester.id,
                target.id,
                amount
            );

        addNotification(
            target.id,
            "KK request",
            `@${requester.username} requested ${amount.toLocaleString()} KK from you.`,
            "kk_request"
        );

        res.json({
            success: true,
            requestId:
                result.lastInsertRowid
        });
    }
);

// =====================================================
// PENDING KK REQUESTS
// =====================================================

app.get(
    "/api/kk/requests/:userId",
    (req, res) => {

        const userId =
            Number(req.params.userId);

        const requests =
            db.prepare(`
                SELECT
                    r.*,
                    u.username AS requester_username
                FROM kk_requests r

                JOIN users u
                    ON u.id = r.requester_id

                WHERE
                    r.target_id = ?
                    AND
                    r.status = 'pending'

                ORDER BY r.id DESC
            `).all(userId);

        res.json({
            success: true,
            requests
        });
    }
);

// =====================================================
// NOTIFICATIONS
// =====================================================

app.get(
    "/api/notifications/:userId",
    (req, res) => {

        const userId =
            Number(req.params.userId);

        const notifications =
            db.prepare(`
                SELECT *
                FROM notifications
                WHERE user_id = ?
                ORDER BY id DESC
                LIMIT 30
            `).all(userId);

        res.json({
            success: true,
            notifications
        });
    }
);

// =====================================================
// MARK NOTIFICATIONS READ
// =====================================================

app.post(
    "/api/notifications/read",
    (req, res) => {

        const userId =
            Number(req.body.userId);

        db.prepare(`
            UPDATE notifications
            SET read = 1
            WHERE user_id = ?
        `).run(userId);

        res.json({
            success: true
        });
    }
);

// =====================================================
// NEWS — EVERYONE CAN READ
// =====================================================

app.get(
    "/api/news",
    (req, res) => {

        const news =
            db.prepare(`
                SELECT *
                FROM news
                ORDER BY id DESC
            `).all();

        res.json({
            success: true,
            news
        });
    }
);

// =====================================================
// GOVERNMENT — CREATE NEWS
// =====================================================

app.post(
    "/api/admin/news",
    (req, res) => {

        const admin =
            requireGovernment(
                req,
                res
            );

        if (!admin) {
            return;
        }

        const organization =
            clean(
                req.body.organization,
                80
            );

        const title =
            clean(
                req.body.title,
                200
            );

        const content =
            clean(
                req.body.content,
                5000
            );

        if (
            !organization ||
            !title ||
            !content
        ) {
            return res.status(400).json({
                error:
                    "Organization, title, and content are required."
            });
        }

        const result =
            db.prepare(`
                INSERT INTO news
                (
                    organization,
                    title,
                    content
                )
                VALUES (?, ?, ?)
            `).run(
                organization,
                title,
                content
            );

        res.json({
            success: true,
            id:
                result.lastInsertRowid
        });
    }
);

// =====================================================
// GOVERNMENT — EDIT NEWS
// =====================================================

app.put(
    "/api/admin/news/:id",
    (req, res) => {

        const admin =
            requireGovernment(
                req,
                res
            );

        if (!admin) {
            return;
        }

        const id =
            Number(req.params.id);

        const organization =
            clean(
                req.body.organization,
                80
            );

        const title =
            clean(
                req.body.title,
                200
            );

        const content =
            clean(
                req.body.content,
                5000
            );

        db.prepare(`
            UPDATE news
            SET
                organization = ?,
                title = ?,
                content = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        `).run(
            organization,
            title,
            content,
            id
        );

        res.json({
            success: true
        });
    }
);

// =====================================================
// GOVERNMENT — DELETE NEWS
// =====================================================

app.delete(
    "/api/admin/news/:id",
    (req, res) => {

        const admin =
            requireGovernment(
                req,
                res
            );

        if (!admin) {
            return;
        }

        db.prepare(`
            DELETE FROM news
            WHERE id = ?
        `).run(
            Number(req.params.id)
        );

        res.json({
            success: true
        });
    }
);

// =====================================================
// ELECTIONS — EVERYONE CAN READ
// =====================================================

app.get(
    "/api/elections",
    (req, res) => {

        const elections =
            db.prepare(`
                SELECT *
                FROM elections
                ORDER BY id DESC
            `).all();

        for (const election of elections) {

            election.candidates =
                db.prepare(`
                    SELECT
                        id,
                        name,
                        vote_count
                    FROM candidates
                    WHERE election_id = ?
                    ORDER BY
                        vote_count DESC,
                        name ASC
                `).all(
                    election.id
                );
        }

        res.json({
            success: true,
            elections
        });
    }
);

// =====================================================
// GOVERNMENT — CREATE ELECTION
// =====================================================

app.post(
    "/api/admin/elections",
    (req, res) => {

        const admin =
            requireGovernment(
                req,
                res
            );

        if (!admin) {
            return;
        }

        const position =
            clean(
                req.body.position,
                100
            );

        const title =
            clean(
                req.body.title,
                150
            );

        const candidates =
            Array.isArray(
                req.body.candidates
            )
                ? req.body.candidates
                : [];

        if (
            !position ||
            !title ||
            !candidates.length
        ) {
            return res.status(400).json({
                error:
                    "Position, title, and at least one candidate are required."
            });
        }

        const electionId =
            db.transaction(() => {

                const election =
                    db.prepare(`
                        INSERT INTO elections
                        (
                            position,
                            title,
                            active
                        )
                        VALUES (?, ?, 1)
                    `).run(
                        position,
                        title
                    );

                const insert =
                    db.prepare(`
                        INSERT INTO candidates
                        (
                            election_id,
                            name,
                            vote_count
                        )
                        VALUES (?, ?, ?)
                    `);

                for (
                    const candidate
                    of candidates
                ) {

                    insert.run(
                        election.lastInsertRowid,
                        clean(
                            candidate.name,
                            100
                        ),
                        Math.max(
                            0,
                            Number(
                                candidate.voteCount
                            ) || 0
                        )
                    );
                }

                return election.lastInsertRowid;
            })();

        res.json({
            success: true,
            id: electionId
        });
    }
);

// =====================================================
// GOVERNMENT — EDIT ELECTION
// =====================================================

app.put(
    "/api/admin/elections/:id",
    (req, res) => {

        const admin =
            requireGovernment(
                req,
                res
            );

        if (!admin) {
            return;
        }

        const electionId =
            Number(req.params.id);

        const position =
            clean(
                req.body.position,
                100
            );

        const title =
            clean(
                req.body.title,
                150
            );

        const active =
            req.body.active
                ? 1
                : 0;

        const candidates =
            Array.isArray(
                req.body.candidates
            )
                ? req.body.candidates
                : [];

        db.transaction(() => {

            db.prepare(`
                UPDATE elections
                SET
                    position = ?,
                    title = ?,
                    active = ?
                WHERE id = ?
            `).run(
                position,
                title,
                active,
                electionId
            );

            db.prepare(`
                DELETE FROM candidates
                WHERE election_id = ?
            `).run(
                electionId
            );

            const insert =
                db.prepare(`
                    INSERT INTO candidates
                    (
                        election_id,
                        name,
                        vote_count
                    )
                    VALUES (?, ?, ?)
                `);

            for (
                const candidate
                of candidates
            ) {

                insert.run(
                    electionId,
                    clean(
                        candidate.name,
                        100
                    ),
                    Math.max(
                        0,
                        Number(
                            candidate.voteCount
                        ) || 0
                    )
                );
            }

        })();

        res.json({
            success: true
        });
    }
);

// =====================================================
// GOVERNMENT — DELETE ELECTION
// =====================================================

app.delete(
    "/api/admin/elections/:id",
    (req, res) => {

        const admin =
            requireGovernment(
                req,
                res
            );

        if (!admin) {
            return;
        }

        db.prepare(`
            DELETE FROM elections
            WHERE id = ?
        `).run(
            Number(req.params.id)
        );

        res.json({
            success: true
        });
    }
);

// =====================================================
// GOVERNMENT — VIEW ALL MEMBERS
// =====================================================

app.get(
    "/api/admin/members",
    (req, res) => {

        const adminId =
            Number(
                req.query.adminId
            );

        const admin =
            getUser(adminId);

        if (
            !admin ||
            !admin.is_admin ||
            admin.username !== "Government"
        ) {
            return res.status(403).json({
                error:
                    "Government access required."
            });
        }

        const members =
            db.prepare(`
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
                ORDER BY
                    username COLLATE NOCASE ASC
            `).all();

        res.json({
            success: true,
            members:
                members.map(
                    userForClient
                )
        });
    }
);

// =====================================================
// GOVERNMENT — GIVE KK
// =====================================================

app.post(
    "/api/admin/kk/give",
    (req, res) => {

        const admin =
            requireGovernment(
                req,
                res
            );

        if (!admin) {
            return;
        }

        const username =
            clean(
                req.body.username,
                20
            );

        const amount =
            Number(req.body.amount);

        const target =
            db.prepare(`
                SELECT *
                FROM users
                WHERE username = ?
            `).get(
                username
            );

        if (!target) {
            return res.status(404).json({
                error:
                    "Account not found."
            });
        }

        if (
            !Number.isInteger(amount) ||
            amount <= 0
        ) {
            return res.status(400).json({
                error:
                    "Invalid amount."
            });
        }

        db.prepare(`
            UPDATE users
            SET balance = balance + ?
            WHERE id = ?
        `).run(
            amount,
            target.id
        );

        createTransaction(
            null,
            target.id,
            amount,
            "government_give",
            "Government gave KK"
        );

        addNotification(
            target.id,
            "KK received",
            `Government gave you ${amount.toLocaleString()} KK.`,
            "kk"
        );

        res.json({
            success: true
        });
    }
);

// =====================================================
// GOVERNMENT — TAKE KK
// =====================================================

app.post(
    "/api/admin/kk/take",
    (req, res) => {

        const admin =
            requireGovernment(
                req,
                res
            );

        if (!admin) {
            return;
        }

        const username =
            clean(
                req.body.username,
                20
            );

        const amount =
            Number(req.body.amount);

        const target =
            db.prepare(`
                SELECT *
                FROM users
                WHERE username = ?
            `).get(
                username
            );

        if (!target) {
            return res.status(404).json({
                error:
                    "Account not found."
            });
        }

        if (
            !Number.isInteger(amount) ||
            amount <= 0
        ) {
            return res.status(400).json({
                error:
                    "Invalid amount."
            });
        }

        if (
            target.balance < amount
        ) {
            return res.status(400).json({
                error:
                    "That account does not have enough KK."
            });
        }

        db.prepare(`
            UPDATE users
            SET balance = balance - ?
            WHERE id = ?
        `).run(
            amount,
            target.id
        );

        createTransaction(
            target.id,
            null,
            amount,
            "government_take",
            "Government took KK"
        );

        addNotification(
            target.id,
            "KK removed",
            `Government removed ${amount.toLocaleString()} KK from your account.`,
            "kk"
        );

        res.json({
            success: true
        });
    }
);

// =====================================================
// GOVERNMENT — SEND NOTIFICATION
// =====================================================

app.post(
    "/api/admin/notify",
    (req, res) => {

        const admin =
            requireGovernment(
                req,
                res
            );

        if (!admin) {
            return;
        }

        const title =
            clean(
                req.body.title,
                100
            ) ||
            "NNR Notification";

        const message =
            clean(
                req.body.message,
                1000
            );

        const targetUsername =
            clean(
                req.body.targetUsername,
                20
            );

        if (!message) {
            return res.status(400).json({
                error:
                    "Notification message is required."
            });
        }

        // Send to one person.
        if (targetUsername) {

            const target =
                db.prepare(`
                    SELECT id
                    FROM users
                    WHERE username = ?
                `).get(
                    targetUsername
                );

            if (!target) {
                return res.status(404).json({
                    error:
                        "Account not found."
                });
            }

            addNotification(
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
        const users =
            db.prepare(`
                SELECT id
                FROM users
            `).all();

        const insert =
            db.prepare(`
                INSERT INTO notifications
                (
                    user_id,
                    title,
                    message,
                    kind
                )
                VALUES (?, ?, ?, 'government')
            `);

        db.transaction(() => {

            for (const user of users) {

                insert.run(
                    user.id,
                    title,
                    message
                );
            }

        })();

        res.json({
            success: true,
            sent: users.length
        });
    }
);

// =====================================================
// START SERVER
// =====================================================

const PORT = 3000;

app.listen(
    PORT,
    "0.0.0.0",
    () => {
        console.log(
            `NNR Server running on http://localhost:${PORT}`
        );
    }
);
