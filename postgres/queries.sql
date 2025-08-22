-- name: GetSigningKeys :many
SELECT id, data FROM signing_key
WHERE id != ANY(@known::text[]);

-- name: AddSigningKey :exec
INSERT INTO signing_key(id, data)
VALUES(@id, @data);
