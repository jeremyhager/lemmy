create table login_token (
  id serial primary key,
  token text not null,
  user_id int REFERENCES local_user ON UPDATE CASCADE ON DELETE CASCADE NOT NULL
);
