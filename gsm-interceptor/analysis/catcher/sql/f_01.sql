DROP VIEW IF EXISTS f1;
-- CREATE VIEW f1 AS
-- SELECT
-- 	si.id,
-- 	min(si2.id),
-- 	si.mcc,
-- 	si.mnc,
-- 	si.lac,
-- 	si.cid,
-- 	count(pag1_rate) as count,
-- 	avg(pag1_rate) < config.min_pag1_rate as score
-- FROM
-- 	session_info AS si, session_info as si2, paging_info AS pi, config
-- ON
-- 	--  Join on the next location update…
-- 	si2.id > si.id AND
-- 	--  …all paging messages since the current location update started…
-- 	strftime('%s', pi.timestamp) - strftime('%s', si.timestamp - si.duration/1000) > 0 AND
-- 	--  …until the succeeding location update starts…
-- 	strftime('%s', si2.timestamp) - si2.duration/1000 - strftime('%s', pi.timestamp) > 0
-- WHERE
-- 	si.domain = 0 AND si2.domain = 0 AND si.lu_acc AND si2.lu_acc
-- GROUP BY
-- 	si.id

CREATE VIEW f1 AS
SELECT
	0 as id,
	0,
	0 as mcc,
	0 as mnc,
	0 as lac,
	0 as cid,
	0 as count,
	0 as score;
