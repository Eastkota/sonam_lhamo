-- DROP TABLE IF EXISTS posts;
-- DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS topics;

-- CREATE TABLE users (
--     id INTEGER PRIMARY KEY AUTOINCREMENT,
--     username TEXT NOT NULL UNIQUE,
--     email TEXT NOT NULL,
--     password TEXT NOT NULL 
-- );

-- CREATE TABLE posts (
--     id INTEGER PRIMARY KEY AUTOINCREMENT,
--     author_id INTEGER NOT NULL,
--     created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
--     title TEXT NOT NULL,
--     content TEXT NOT NULL,
--     FOREIGN KEY (author_id) REFERENCES users (id)
-- );
CREATE TABLE topics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id INTEGER NOT NULL,
    created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    subject TEXT NOT NULL,
    topics TEXT NOT NULL,
    time_spent INTEGER NOT NULL,
    FOREIGN KEY (author_id) REFERENCES users (id)
);
