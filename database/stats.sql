SELECT CONCAT(YEAR(created_at), "-", LPAD(MONTH(created_at),2,"0")) AS date, COUNT(1) AS num
FROM issuers
GROUP BY YEAR(created_at), MONTH(created_at);

SELECT CONCAT(YEAR(created_at), "-", LPAD(MONTH(created_at),2,"0")) AS date, COUNT(1) AS num
FROM results
GROUP BY YEAR(created_at), MONTH(created_at);

