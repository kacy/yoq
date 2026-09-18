# storage api

the storage gateway is a small, s3-style api at `/s3/{bucket}/{key}`. it uses the yoq api bearer token. it does not implement aws signature version 4, so an unmodified aws sdk is not a supported client.

the gateway supports bucket creation, listing and deletion; object put, get, head and delete; paginated object listing; and multipart initiation, part upload, completion and abort. keys and listing prefixes accept percent encoding. get and head return the object's md5 etag in the `ETag` header. head has no response body and reports the object size in `Content-Length`.

object listings are sorted by key. `prefix`, `start-after`, `max-keys` (0–1,000), and `continuation-token` select a page. when `IsTruncated` is true, pass `NextContinuationToken` unchanged to the next request. a listing is not a snapshot: concurrent writes or deletes can affect later pages.

multipart completion requires a `CompleteMultipartUpload` xml body containing ascending `Part` entries, each with a `PartNumber` and the uploaded part's `ETag`. completion uses only those parts and rejects missing parts or mismatched etags. the completed object's etag is its content md5; it does not use the aws multipart etag convention.

writes are staged outside the bucket tree. the gateway syncs the complete candidate, renames it into place, and syncs the destination and staging directories before reporting success. an interrupted write before rename preserves the old object. a failure after rename can leave the new, complete object visible even though the request failed; retrying the same put is safe. staging and bucket directories must be on the same filesystem. crash leftovers in `s3-pending` are not visible through listings.

object get and put still use the api server's buffered request and response path. this gateway does not provide streaming large-object transfers, range requests, object versioning, lifecycle policies, or a complete s3 compatibility contract.
