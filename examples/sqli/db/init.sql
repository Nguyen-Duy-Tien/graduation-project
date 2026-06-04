-- init SQL for vuln DB (extended with more "secret" fields)
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100) NOT NULL UNIQUE,
  password VARCHAR(100) NOT NULL,
  role VARCHAR(20),
  full_info TEXT,
  email VARCHAR(150),
  cc_number VARCHAR(64),
  api_key VARCHAR(128)
);

CREATE TABLE IF NOT EXISTS customers (
  id INT AUTO_INCREMENT PRIMARY KEY,
  first_name VARCHAR(100),
  last_name VARCHAR(100),
  email VARCHAR(200)
);

-- sample users with "secrets"
INSERT INTO users (username, password, role, full_info, email, cc_number, api_key) VALUES
('alice','alicepass','user','Alice profile info','alice@example.com','4111111111111111','apikey_alice_12345'),
('bob','bobpass','user','Bob profile info','bob@example.com','5555444433332222','apikey_bob_98765'),
('admin','adminpass','admin','Administrator account (sensitive)','admin@example.com','378282246310005','apikey_admin_SUPERSECRET');

INSERT INTO customers (first_name, last_name, email) VALUES
('John','Doe','john@example.com'),
('Jane','Smith','jane@example.com'),
('Evil','Hacker','evil@example.com');

-- keep the file idempotent
