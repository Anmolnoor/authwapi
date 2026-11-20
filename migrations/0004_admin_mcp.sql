create table "adminKey" ("id" text not null primary key, "keyHash" text not null unique, "scope" text not null, "createdAt" date not null, "expiresAt" date, "revokedAt" date);
