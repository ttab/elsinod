-- Assuming swedish as default here, only works because we're in internal
-- pre-production.
UPDATE document AS d
       SET language = coalesce(v.document_data->>'language', 'sv-se')
FROM document_version AS v
     WHERE v.uuid = d.uuid
           AND v.version = d.current_version
           AND d.language IS NULL;

UPDATE eventlog AS e
       SET language = d.language
FROM document AS d
     WHERE d.uuid = e.uuid
     AND e.language IS NULL;

UPDATE status_heads AS s
       SET language = d.language
FROM document AS d
     WHERE d.uuid = s.uuid
     AND s.language IS NULL;

UPDATE acl_audit AS a
       SET language = d.language
FROM document AS d
     WHERE d.uuid = a.uuid
     AND a.language IS NULL;

-- We're still not running any real workloads, let's drop all delete records
-- instead of migrating.
DELETE FROM delete_record;

ALTER TABLE document
      ALTER COLUMN language SET NOT NULL;

ALTER TABLE eventlog
      ALTER COLUMN language SET NOT NULL;

ALTER TABLE status_heads
      ALTER COLUMN language SET NOT NULL;

ALTER TABLE acl_audit
      ALTER COLUMN language SET NOT NULL;

ALTER TABLE delete_record
      ALTER COLUMN language SET NOT NULL;
