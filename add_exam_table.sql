-- SQLite
CREATE TABLE Exam (
    id INTEGER PRIMARY KEY,
    id_user INTEGER NOT NULL,
    questions TEXT NOT NULL,
    num_questions INTEGER NOT NULL,
    identifier TEXT NOT NULL,
    FOREIGN KEY (id_user) REFERENCES User(id)
);
