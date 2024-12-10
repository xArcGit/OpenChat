import { Database } from "bun:sqlite";
import type { ServerWebSocket } from "bun";
import { Hono } from "hono";
import { createBunWebSocket } from "hono/bun";
import { cors } from "hono/cors";
import { nanoid } from "nanoid";

const app = new Hono();
const connections = new Map();
const { upgradeWebSocket, websocket } = createBunWebSocket<WebSocket>();

const db = new Database("db.sqlite", { strict: true });

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    uid TEXT PRIMARY KEY, 
    username TEXT UNIQUE, 
    publicKey TEXT
  );
`);
db.exec(`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT,
    recipient TEXT,
    message TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    delivered BOOLEAN DEFAULT 0
  );
`);

// WebSocket route for real-time communication
app.get(
	"/",
	upgradeWebSocket((ctx) => ({
		/**
		 * Event triggered when a new WebSocket connection is opened.
		 * @param {object} event - Event object.
		 * @param {WebSocket} ws - The WebSocket instance.
		 */
		onOpen(event, ws) {
			console.log("Connection opened. Waiting for client to send clientId...");
		},

		/**
		 * Event triggered when a message is received via WebSocket.
		 * Handles registration or message routing to online/offline recipients.
		 * @param {object} event - Event object containing the received message.
		 * @param {WebSocket} ws - The WebSocket instance.
		 */
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
						"INSERT INTO messages (sender, recipient, message, delivered) VALUES ($sender, $recipient, $message, 0)",
					);
					insertMessage.run(sender, recipient, content);
				}
			} catch (error) {
				ws.send(JSON.stringify({ error: "Invalid JSON format in message." }));
				console.error("Error processing message:", error);
			}
		},

		/**
		 * Event triggered when a WebSocket connection is closed.
		 * Cleans up the connections map.
		 * @param {WebSocket} ws - The WebSocket instance.
		 */
		onClose(ws) {
			const clientId = Array.from(connections.entries()).find(
				([key, socket]) => socket === ws,
			)?.[0];
			if (clientId) {
				connections.delete(clientId);
			}
		},

		/**
		 * Event triggered when a WebSocket encounters an error.
		 * @param {WebSocket} ws - The WebSocket instance.
		 * @param {Error} error - The error that occurred.
		 */
		onError(ws, error) {
			console.error("WebSocket error:", error);
		},
	})),
);

// REST route for user registration
app.post("/register", async (c) => {
	/**
	 * Handles user registration by storing their username and public key.
	 * Responds with the registered user details or an error.
	 */
	const { username, publicKey } = await c.req.json();

	if (!username || !publicKey) {
		return c.json({ error: "Username and publicKey are required" }, 400);
	}

	const checkUserQuery = db.prepare(
		"SELECT * FROM users WHERE username = $param;",
	);
	const existingUser = checkUserQuery.get(username);

	if (existingUser) {
		return c.json({ error: "Username already exists" }, 400);
	}

	const insertUser = db.prepare(
		"INSERT INTO users (uid, username, publicKey) VALUES ($uid, $username, $publicKey);",
	);
	const uid = nanoid();
	insertUser.run(uid, username, publicKey);

	return c.json(
		{
			message: "User registered successfully",
			uid: uid,
			username: username,
			publicKey: publicKey,
		},
		201,
	);
});

// REST route to fetch user details by username
app.get("/user", (c) => {
	/**
	 * Retrieves user information based on the provided username.
	 * Responds with user details or an error if the user is not found.
	 */
	const username = c.req.query("username");

	if (!username) {
		return c.json({ error: "Username is required" }, 400);
	}

	const getUserQuery = db.prepare(
		"SELECT * FROM users WHERE username = $param;",
	);
	const user = getUserQuery.get(username);

	if (!user) {
		return c.json({ error: "User not found" }, 404);
	}

	return c.json({ user }, 200);
});

// REST route to fetch undelivered messages for a recipient
app.get("/messages", (c) => {
	/**
	 * Retrieves undelivered messages for the specified recipient.
	 * Marks retrieved messages as delivered.
	 */
	const recipient = c.req.query("recipient");

	if (!recipient) {
		return c.json({ error: "Recipient is required" }, 400);
	}

	const fetchMessages = db.prepare(
		"SELECT sender, message, timestamp FROM messages WHERE recipient = $param AND delivered = 0 ORDER BY timestamp DESC;",
	);

	const userMessages = fetchMessages.all(recipient);
	if (userMessages.length === 0) {
		return c.json({ message: "No messages found for the recipient." }, 200);
	}

	// const markMessagesDelivered = db.prepare(
	// 	"UPDATE messages SET delivered = 1 WHERE recipient = $param AND delivered = 0;",
	// );
	// markMessagesDelivered.run(recipient);

	return c.json({ messages: userMessages });
});

// REST route to save a new message
app.post("/messages", async (c) => {
	/**
	 * Stores a new message in the database.
	 * Marks the message as undelivered if the recipient is offline.
	 */
	const { sender, recipient, message } = await c.req.json();

	if (!sender || !recipient || !message) {
		return c.json(
			{ error: "Sender, recipient, and message are required" },
			400,
		);
	}

	const insertMessage = db.prepare(
		"INSERT INTO messages (sender, recipient, message, delivered) VALUES ($sender, $recipient, $message, 0)",
	);
	insertMessage.run(sender, recipient, message);
	return c.json({ message: "Message sent successfully" }, 201);
});

export default {
	fetch: app.fetch,
	websocket,
};
