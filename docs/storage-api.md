# storage api

the storage gateway is a small, s3-style api at `/s3/{bucket}/{key}`. it uses the yoq api bearer token. it does not implement aws signature version 4, so an unmodified aws sdk is not a supported client.

the gateway supports bucket creation, listing and deletion; object put, get, head and delete; paginated object listing; and multipart initiation, part upload, completion and abort. keys and listing prefixes accept percent encoding. object keys use canonical relative paths: empty components, single-dot components, repeated slashes, and trailing slashes are rejected. an object named `a` cannot coexist with `a/b`, because objects use the host directory tree. get and head return the object's md5 etag in the `ETag` header. head has no response body and reports the object size in `Content-Length`.

object listings are sorted by key. `prefix`, `start-after`, `max-keys` (0–1,000), and `continuation-token` select a page. when `IsTruncated` is true, pass `NextContinuationToken` unchanged to the next request. a listing is not a snapshot: concurrent writes or deletes can affect later pages.

multipart completion requires a `CompleteMultipartUpload` xml body containing ascending `Part` entries, each with a `PartNumber` and the uploaded part's `ETag`. completion uses only those parts and rejects missing parts or mismatched etags. the completed object's etag is its content md5; it does not use the aws multipart etag convention.

writes are staged outside the bucket tree. the gateway syncs the complete candidate, renames it into place, and syncs the destination and staging directories before reporting success. an interrupted write before rename preserves the old object. a failure after rename can leave the new, complete object visible even though the request failed; retrying the same put is safe. staging and bucket directories must be on the same filesystem. crash leftovers in `s3-pending` are not visible through listings.

object get streams from an open file with a 16 kib copy buffer. metadata and content use the same descriptor, so a concurrent replacement or deletion does not change an in-progress download. get supports objects larger than 256 mib, including completed multipart uploads. the api admits at most 128 connections, which bounds simultaneous object-copy buffers to 2 mib. response writes retain the api's five-second transfer deadline; a timed-out transfer closes the connection and must be retried.

put and part uploads remain buffered, with a 256 mib limit per request and a shared request-memory budget. multipart completion copies up to 10,000 selected parts through an 8 kib buffer. get and head still read the object to compute its etag before sending headers; this can delay responses for large objects. the gateway does not provide range requests, object versioning, lifecycle policies, or a complete s3 compatibility contract.
