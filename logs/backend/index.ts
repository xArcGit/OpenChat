import { Database } from "bun:sqlite";
import type { ServerWebSocket } from "bun";
import { Hono } from "hono";
import { createBunWebSocket } from "hono/bun";
import { logger } from "hono/logger";

const app = new Hono();
app.use(logger());
const connections = new Map();
const { upgradeWebSocket, websocket } = createBunWebSocket<ServerWebSocket>();

const db = new Database("db.sqlite", { strict: true });

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY, 
    publicKey TEXT
  );
`);
db.exec(`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT,
    recipient TEXT,
    message TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

app.get(
	"/",
	upgradeWebSocket((ctx) => ({
		onOpen(event, ws) {
			console.log("Connection opened. Waiting for client to send clientId... ");
		},

		onMessage(event, ws) {
			try {
				const parsedMessage = JSON.parse(event.data as string);

				if (parsedMessage.type === "register") {
					const { clientId } = parsedMessage;
					if (!clientId) {
						ws.send(
							JSON.stringify({
								error: "clientId is required for registration.",
							}),
						);
						return;
					}

					connections.set(clientId, ws);
					ws.send(JSON.stringify({ type: "registered", clientId }));
					return;
				}

				const { sender, recipient, content } = parsedMessage;
				if (!sender || !recipient || !content) {
					ws.send(
						JSON.stringify({
							error:
								"Invalid message format. Expected sender, recipient, and content.",
						}),
					);
					return;
				}

				const recipientSocket = connections.get(recipient);
				if (recipientSocket) {
					recipientSocket.send(JSON.stringify({ sender, message: content }));
				} else {
					const insertMessage = db.prepare(
						"INSERT INTO messages (sender, recipient, message) VALUES ($sender, $recipient, $message)",
					);
					insertMessage.run(sender, recipient, content);
				}
			} catch (error) {
				ws.send(JSON.stringify({ error: "Invalid JSON format in message." }));
				console.error("Error processing message:", error);
			}
		},

		onClose(ws) {
			const clientId = Array.from(connections.entries()).find(
				([key, socket]) => socket === ws,
			)?.[0];
			if (clientId) {
				connections.delete(clientId);
			}
		},

		onError(ws, error) {
			console.error("WebSocket error:", error);
		},
	})),
);

app.post("/register", async (c) => {
	const { username, publicKey } = await c.req.json();

	if (!username || !publicKey) {
		return c.json(400);
	}

	const checkUserQuery = db.prepare(
		"SELECT * FROM users WHERE username = $param;",
	);
	const existingUser = checkUserQuery.get(username);

	if (existingUser) {
		return c.json(400);
	}

	const insertUser = db.prepare(
		"INSERT INTO users (username, publicKey) VALUES ($username, $publicKey);",
	);
	insertUser.run(username, publicKey);

	return c.json(201);
});

app.get("/user", (c) => {
	const username = c.req.query("username");

	if (!username) {
		return c.json(400);
	}

	const getUserQuery = db.prepare(
		"SELECT * FROM users WHERE username = $param;",
	);
	const user = getUserQuery.get(username);

	if (!user) {
		return c.json(404);
	}

	return c.json({ user }, 200);
});

app.get("/messages", (c) => {
	const recipient = c.req.query("recipient");
	const sender = c.req.query("sender");

	if (!recipient || !sender) {
		return c.json(400);
	}
	const fetchMessages = db.prepare(
		"SELECT message FROM messages WHERE recipient = $recipient AND sender = $sender ORDER BY timestamp DESC;",
	);

	const messages = fetchMessages.all(recipient, sender);
	const formattedMessages = (messages as { message: string }[]).map(
		(msg) => msg.message,
	);

	if (messages.length === 0) {
		return c.json(200);
	}

	// const deleteMessages = db.prepare(
	// 	"DELETE FROM messages WHERE recipient = $recipient AND sender = $sender;",
	// );
	// deleteMessages.run(recipient, sender);

	return c.json({ messages: formattedMessages });
});

app.post("/messages", async (c) => {
	const { sender, recipient, message } = await c.req.json();

	if (!sender || !recipient || !message) {
		return c.json(
			{ error: "Sender, recipient, and message are required" },
			400,
		);
	}

	const insertMessage = db.prepare(
		"INSERT INTO messages (sender, recipient, message) VALUES ($sender, $recipient, $message)",
	);
	insertMessage.run(sender, recipient, message);
	return c.json({ message: "Message sent successfully" }, 201);
});

export default {
	fetch: app.fetch,
	websocket,
};
