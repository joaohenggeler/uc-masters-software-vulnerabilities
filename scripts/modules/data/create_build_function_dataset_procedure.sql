DROP PROCEDURE IF EXISTS BUILD_FUNCTION_DATASET;

DELIMITER $$

CREATE PROCEDURE BUILD_FUNCTION_DATASET(IN iMETRICS_TABLE VARCHAR(200), IN iOUTPUT_CSV_PATH VARCHAR(3000),
										IN iFILTER_INELIGIBLE_SAMPLES BOOLEAN, IN iFILTER_COMMITS_WITHOUT_ALERTS BOOLEAN,
										IN iALLOWED_SAT_NAME_LIST VARCHAR(100))
BEGIN
	DECLARE vEXTRA_WHERE_CONDITION VARCHAR(100) DEFAULT '';
	DECLARE vALERT_COLUMNS VARCHAR(10000);
	DECLARE vALERT_SELECT VARCHAR(10000);
	DECLARE vALERT_COUNT VARCHAR(10000);
	DECLARE vMETRICS_COLUMNS VARCHAR(10000);

	IF iFILTER_INELIGIBLE_SAMPLES THEN
		-- Using the column ELIGIBLE_FOR_ALERTS didn't work for the where condition.
		SET vEXTRA_WHERE_CONDITION = CONCAT(vEXTRA_WHERE_CONDITION, ' AND (U.BeginLine IS NOT NULL AND U.EndLine IS NOT NULL)');
	END IF;

	IF iFILTER_COMMITS_WITHOUT_ALERTS THEN
		SET vEXTRA_WHERE_CONDITION = CONCAT(vEXTRA_WHERE_CONDITION, ' AND JAC.COMMIT_HAS_ALERTS = 1');
	END IF;

	SET @@session.group_concat_max_len = 100000;

	SELECT
		GROUP_CONCAT(CONCAT('"', FEATURE_NAME, '"')),
		GROUP_CONCAT(CONCAT('IFNULL(`', FEATURE_NAME, '`, 0) AS `', FEATURE_NAME, '`')),
		GROUP_CONCAT(
			CONCAT(	'COUNT(CASE WHEN SAT_NAME = "', SAT_NAME, '"',
					' AND RULE_NAME = "', RULE_NAME, '"',
					' THEN 1 END) AS `', FEATURE_NAME, '`')
		)
	INTO vALERT_COLUMNS, vALERT_SELECT, vALERT_COUNT
	FROM
	(
		SELECT SAT_NAME, RULE_NAME, CONCAT(REPLACE(SAT_NAME, ' ', ''), '_', REPLACE(RULE_NAME, ' ', '')) AS FEATURE_NAME
	    FROM RULE AS R INNER JOIN SAT S ON R.SAT_ID = S.SAT_ID
	    WHERE FIND_IN_SET(SAT_NAME, iALLOWED_SAT_NAME_LIST)
		GROUP BY SAT_NAME, RULE_NAME
	) SAT_RULE;

	SELECT GROUP_CONCAT(CONCAT('"', COLUMN_NAME, '"') ORDER BY ORDINAL_POSITION)
	INTO vMETRICS_COLUMNS
 	FROM INFORMATION_SCHEMA.COLUMNS
	WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'FUNCTIONS_5';

	-- Needs to be a user variable because of PREPARE STATEMENT.
	SET @QUERY = CONCAT(
		'(SELECT 	"Description", "COMMIT_HASH", "COMMIT_DATE", "COMMIT_YEAR", "VULNERABILITY_CVE", "VULNERABILITY_YEAR",
					"VULNERABILITY_CWE", "VULNERABILITY_CATEGORY", ', vMETRICS_COLUMNS, ', "ELIGIBLE_FOR_ALERTS", "COMMIT_HAS_ALERTS", "TOTAL_ALERTS", ', vALERT_COLUMNS,
		')
		
		UNION ALL
		
		SELECT 	REPLACE(CONCAT(U.R_ID, "_", JV.COMMIT_HASH, "_", U.FilePath, "_", U.NameMethod), " ", "_") AS Description,
				
				JV.COMMIT_HASH,
				JV.COMMIT_DATE,
				JV.COMMIT_YEAR,
				JV.VULNERABILITY_CVE,
				JV.VULNERABILITY_YEAR,
				JV.VULNERABILITY_CWE,
				IFNULL(JV.VULNERABILITY_CATEGORY, "Other") AS VULNERABILITY_CATEGORY,
				
				U.*,
				(U.BeginLine IS NOT NULL AND U.EndLine IS NOT NULL) AS ELIGIBLE_FOR_ALERTS,
				IFNULL(JAC.COMMIT_HAS_ALERTS, 0) AS COMMIT_HAS_ALERTS,
				IFNULL(JA.TOTAL_ALERTS, 0) AS TOTAL_ALERTS,',
				vALERT_SELECT,
		'FROM ', iMETRICS_TABLE, ' AS U
	    
	    LEFT JOIN
		(
			SELECT AF.ID_Function, COUNT(*) AS TOTAL_ALERTS, ', vALERT_COUNT,
			'
			FROM ALERT_FUNCTION AF
			INNER JOIN ALERT A ON AF.ALERT_ID = A.ALERT_ID
			INNER JOIN RULE R ON A.RULE_ID = R.RULE_ID
			INNER JOIN SAT S ON R.SAT_ID = S.SAT_ID
			GROUP BY AF.ID_Function
		) JA ON U.ID_Function = JA.ID_Function
	    
	    LEFT JOIN
	    (
			SELECT 	E.ID_File,
					
					SUBSTRING_INDEX(GROUP_CONCAT(P.P_COMMIT ORDER BY P.DATE, V.CVE), ",", 1) AS COMMIT_HASH,
					SUBSTRING_INDEX(GROUP_CONCAT(P.DATE ORDER BY P.DATE, V.CVE), ",", 1) AS COMMIT_DATE,
					REGEXP_SUBSTR(SUBSTRING_INDEX(GROUP_CONCAT(P.DATE ORDER BY P.DATE, V.CVE), ",", 1), "[0-9]+") AS COMMIT_YEAR,
					
					SUBSTRING_INDEX(GROUP_CONCAT(V.CVE ORDER BY P.DATE, V.CVE), ",", 1) AS VULNERABILITY_CVE,
					REGEXP_SUBSTR(SUBSTRING_INDEX(GROUP_CONCAT(V.CVE ORDER BY P.DATE, V.CVE), ",", 1), "[0-9]+") AS VULNERABILITY_YEAR,
					SUBSTRING_INDEX(GROUP_CONCAT(V.V_CWE ORDER BY P.DATE, V.CVE), ",", 1) AS VULNERABILITY_CWE,
					SUBSTRING_INDEX(GROUP_CONCAT(VC.NAME ORDER BY P.DATE, V.CVE), ",", 1) AS VULNERABILITY_CATEGORY

			FROM EXTRA_TIME_FILES E
			INNER JOIN PATCHES P ON E.P_ID = P.P_ID
			INNER JOIN VULNERABILITIES V ON P.V_ID = V.V_ID
	        LEFT JOIN CWE_INFO CI ON V.V_CWE = CI.V_CWE
	        LEFT JOIN VULNERABILITY_CATEGORY VC ON CI.ID_CATEGORY = VC.ID_CATEGORY
			GROUP BY E.ID_File
	    ) JV ON U.ID_File = JV.ID_File
	    
		LEFT JOIN
		(
			SELECT A.R_ID, A.P_COMMIT, A.P_OCCURRENCE, COUNT(*) > 0 AS COMMIT_HAS_ALERTS
			FROM ALERT A
			GROUP BY A.R_ID, A.P_COMMIT, A.P_OCCURRENCE
		) JAC ON U.R_ID = JAC.R_ID AND JV.COMMIT_HASH = JAC.P_COMMIT AND U.Occurrence = JAC.P_OCCURRENCE

	    WHERE JV.COMMIT_HASH IS NOT NULL ', vEXTRA_WHERE_CONDITION,
	    '
	    
	    INTO OUTFILE "', iOUTPUT_CSV_PATH, '"
		FIELDS TERMINATED BY ","
		OPTIONALLY ENCLOSED BY """"
		ESCAPED BY ""
		LINES TERMINATED BY "\n"
		;'
	);

	PREPARE STATEMENT FROM @QUERY;
	EXECUTE STATEMENT;
	DEALLOCATE PREPARE STATEMENT;

END$$

DELIMITER ;