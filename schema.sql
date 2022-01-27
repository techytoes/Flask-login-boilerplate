DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS photos;
CREATE TABLE users (
    id VARCHAR(40) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
);
CREATE TABLE photos (
    id VARCHAR(40) PRIMARY KEY,
    url VARCHAR(255) NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id)
);