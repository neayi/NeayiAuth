CREATE TABLE neayiauth_users (
    neayiauth_user INTEGER NOT NULL PRIMARY KEY,
    neayiauth_external_userid INTEGER NOT NULL UNIQUE
);