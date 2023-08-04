CREATE TABLE login_token (
    id serial PRIMARY KEY,
    token text NOT NULL,
    user_id int REFERENCES local_user ON UPDATE CASCADE ON DELETE CASCADE NOT NULL
);

