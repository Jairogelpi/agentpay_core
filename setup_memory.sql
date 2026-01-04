-- 1. Enable Vector Extension
create extension if not exists vector;

-- 2. Add Embedding Column (1536 dims for text-embedding-3-small)
alter table transaction_logs
add column if not exists embedding vector(1536);

-- 3. Create Search Function (This MUST match the names in ai_guard.py)
drop function if exists match_transactions;

create or replace function match_transactions (
  query_embedding vector(1536),
  match_threshold float,
  match_count int
)
returns setof transaction_logs
language plpgsql
as $$
begin
  return query
  select *
  from transaction_logs
  where transaction_logs.embedding <=> query_embedding < 1 - match_threshold
  order by transaction_logs.embedding <=> query_embedding asc
  limit match_count;
end;
$$;

-- 4. Create Index for Speed
create index on transaction_logs using hnsw (embedding vector_cosine_ops);
