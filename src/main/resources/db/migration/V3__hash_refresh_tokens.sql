-- Refresh tokens passam a ser guardados como SHA-256 (hex) do valor entregue ao cliente.
-- Os valores já gravados em texto puro são convertidos com o mesmo hash, então o cliente
-- continua válido: o servidor compara sha256(valor_recebido) com a coluna.
ALTER TABLE refresh_tokens RENAME COLUMN token TO token_hash;

UPDATE refresh_tokens
SET token_hash = encode(sha256(convert_to(token_hash, 'UTF8')), 'hex');
