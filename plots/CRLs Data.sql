-- SELECT *, CEIL(crl_size/used_by) AS amortized_cost FROM (SELECT crl_uri, crl_size, num_of_revoked, COUNT(cert_id) AS used_by FROM certs_crls join crls_uri on certs_crls.crl_uri_id = crls_uri.crl_uri_id JOIN crls ON crls.crl_uri_id = crls_uri.crl_uri_id where num_of_revoked > 0 GROUP BY certs_crls.crl_uri_id ORDER BY used_by DESC) AS temp ORDER BY amortized_cost;
/*
SELECT temp1.range1, COUNT(*) FROM
	(SELECT CASE
		WHEN num_of_revoked = 0 THEN '0'
		WHEN num_of_revoked BETWEEN 1 AND 10 THEN '1-10'
		WHEN num_of_revoked BETWEEN 11 AND 20 THEN '11-20'
		WHEN num_of_revoked BETWEEN 21 AND 30 THEN '21-30'
		WHEN num_of_revoked BETWEEN 31 AND 40 THEN '31-40'
		WHEN num_of_revoked BETWEEN 41 AND 50 THEN '41-50'
		WHEN num_of_revoked BETWEEN 51 AND 60 THEN '51-60'
		WHEN num_of_revoked BETWEEN 61 AND 70 THEN '61-70'
		WHEN num_of_revoked BETWEEN 71 AND 80 THEN '71-80'
		WHEN num_of_revoked BETWEEN 81 AND 90 THEN '81-90'
		WHEN num_of_revoked BETWEEN 91 AND 100 THEN '91-100'
		WHEN num_of_revoked BETWEEN 101 AND 200 THEN '101-200'
		WHEN num_of_revoked BETWEEN 201 AND 300 THEN '201-300'
		WHEN num_of_revoked BETWEEN 301 AND 400 THEN '301-400'
		WHEN num_of_revoked BETWEEN 401 AND 500 THEN '401-500'
		WHEN num_of_revoked BETWEEN 501 AND 600 THEN '501-600'
		WHEN num_of_revoked BETWEEN 601 AND 700 THEN '601-700'
		WHEN num_of_revoked BETWEEN 701 AND 800 THEN '701-800'
		WHEN num_of_revoked BETWEEN 801 AND 900 THEN '801-900'
		WHEN num_of_revoked BETWEEN 901 AND 1000 THEN '901-1000'
		WHEN num_of_revoked BETWEEN 1001 AND 1500 THEN '1001-1500'
		WHEN num_of_revoked BETWEEN 1501 AND 2000 THEN '1501-2000'
		WHEN num_of_revoked BETWEEN 2001 AND 2500 THEN '2001-2500'
		WHEN num_of_revoked BETWEEN 2501 AND 3000 THEN '2501-3000'
		WHEN num_of_revoked BETWEEN 3001 AND 3500 THEN '3001-3500'
		WHEN num_of_revoked BETWEEN 3501 AND 4000 THEN '3501-4000'
		WHEN num_of_revoked BETWEEN 4001 AND 4500 THEN '4001-4500'
		WHEN num_of_revoked BETWEEN 4501 AND 5000 THEN '4501-5000'
		WHEN num_of_revoked BETWEEN 5001 AND 5500 THEN '5001-5500'
		WHEN num_of_revoked BETWEEN 5501 AND 6000 THEN '5501-6000'
		WHEN num_of_revoked BETWEEN 6001 AND 6500 THEN '6001-6500'
		WHEN num_of_revoked BETWEEN 6501 AND 7000 THEN '6501-7000'
		WHEN num_of_revoked BETWEEN 7001 AND 7500 THEN '7001-7500'
		WHEN num_of_revoked BETWEEN 7501 AND 8000 THEN '7501-8000'
		WHEN num_of_revoked BETWEEN 8001 AND 8500 THEN '8001-8500'
		WHEN num_of_revoked BETWEEN 8501 AND 9000 THEN '8501-9000'
		WHEN num_of_revoked BETWEEN 9001 AND 9500 THEN '9001-9500'
		WHEN num_of_revoked BETWEEN 9501 AND 10000 THEN '9501-10000'
		ELSE 'Above 10000' END AS range1
		FROM crls) AS temp1
	GROUP BY temp1.range1;
*/

UPDATE CRL.certs SET parent_cert_id = NULL;
DELETE FROM certs;