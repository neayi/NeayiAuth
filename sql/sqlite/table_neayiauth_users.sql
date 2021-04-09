CREATE TABLE /*_*/neayiauth_users (
    neayiauth_user int unsigned PRIMARY KEY NOT NULL,
    neayiauth_external_userid  VARCHAR(255) UNIQUE NOT NULL,
    neayiauth_external_apitoken VARCHAR(255) UNIQUE NOT NULL
) /*$wgDBTableOptions*/;