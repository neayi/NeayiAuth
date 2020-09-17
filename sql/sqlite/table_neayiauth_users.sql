CREATE TABLE /*_*/neayiauth_users (
    neayiauth_user int unsigned PRIMARY KEY NOT NULL,
    neayiauth_external_userid  int unsigned UNIQUE NOT NULL
) /*$wgDBTableOptions*/;