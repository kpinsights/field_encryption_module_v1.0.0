<?php
namespace CERCHECW\FieldEncryptionModule;

use ExternalModules\AbstractExternalModule;

require_once __DIR__ . '/UnsafeCrypto.php';
require_once __DIR__ . '/SaferCrypto.php';

/**
 * Field Encryption Module for REDCap
 *
 * Encrypts fields tagged with @ENCRYPT. Email fields get stored as ENC_[base64]@xx.xx
 * so they pass REDCap's validation but remain unreadable. A cron job decrypts
 * emails when sending automated survey invitations.
 *
 * @author Kshitiz Pokhrel <kpokhrel@torontomu.ca>
 * @author Ryan McRonald <rmcronald@uvic.ca>
 */
class FieldEncryptionModule extends AbstractExternalModule
{
    // Keeps track of records we're currently processing to avoid infinite loops
    private static $processingRecord = [];

    /**
     * Gets the encryption key from system settings
     */
    private function getEncryptionKey()
    {
        $keyHex = $this->getSystemSetting('encryption-key');
        if (empty($keyHex)) {
            throw new \Exception('Encryption key not configured');
        }
        return hex2bin($keyHex);
    }

    /**
     * Looks up which fields have the @ENCRYPT action tag
     */
    private function getFieldsToEncrypt($project_id = null)
    {
        $project_id = $project_id ?? $this->getProjectId();
        $dictionary = \REDCap::getDataDictionary($project_id, 'array');

        if (empty($dictionary)) {
            return [];
        }

        $fieldsToEncrypt = [];
        foreach ($dictionary as $fieldName => $fieldInfo) {
            $actionTags = $fieldInfo['field_annotation'] ?? '';
            if (stripos($actionTags, '@ENCRYPT') !== false) {
                $fieldsToEncrypt[] = $fieldName;
            }
        }
        return $fieldsToEncrypt;
    }

    /**
     * Encrypts a value and formats it as a fake email address
     * Output format: ENC_[url-safe-base64]@xx.xx
     */
    public function encryptValue($plaintext)
    {
        $key = $this->getEncryptionKey();
        $encrypted = SaferCrypto::encrypt($plaintext, $key, true);

        // Make it URL-safe: swap +/ for -_ and drop padding
        $urlSafe = rtrim(strtr($encrypted, '+/', '-_'), '=');
        return 'ENC_' . $urlSafe . '@xx.xx';
    }

    /**
     * Decrypts a value if it matches our encrypted format
     */
    public function decryptValue($encryptedValue)
    {
        // Not our format? Return as-is
        if (strpos($encryptedValue, '@xx.xx') === false) {
            return $encryptedValue;
        }

        $localPart = substr($encryptedValue, 0, strpos($encryptedValue, '@'));
        if (strpos($localPart, 'ENC_') !== 0) {
            return $encryptedValue;
        }

        // Strip the ENC_ prefix and convert back to standard base64
        $urlSafeBase64 = substr($localPart, 4);
        $base64 = strtr($urlSafeBase64, '-_', '+/');

        // Restore padding
        $remainder = strlen($base64) % 4;
        if ($remainder) {
            $base64 .= str_repeat('=', 4 - $remainder);
        }

        $key = $this->getEncryptionKey();
        return SaferCrypto::decrypt($base64, $key, true);
    }

    /**
     * Hook: runs after a record is saved via data entry
     */
    public function redcap_save_record($project_id, $record, $instrument, $event_id, $group_id, $survey_hash, $response_id, $repeat_instance)
    {
        $this->encryptRecordData($project_id, $record, $instrument, $event_id, $repeat_instance);
    }

    /**
     * Hook: runs after a survey is submitted
     */
    public function redcap_survey_complete($project_id, $record, $instrument, $event_id, $group_id, $survey_hash, $response_id, $repeat_instance)
    {
        $this->encryptRecordData($project_id, $record, $instrument, $event_id, $repeat_instance);
    }

    /**
     * Main encryption logic, fetches record data and encrypts tagged fields
     */
    private function encryptRecordData($project_id, $record, $instrument, $event_id, $repeat_instance)
    {
        $repeat_instance = $repeat_instance ?: 1;
        $recordKey = "$project_id:$record:$event_id:$repeat_instance";

        // Bail out if we're already processing this record (prevents loops)
        if (isset(self::$processingRecord[$recordKey])) {
            return;
        }
        self::$processingRecord[$recordKey] = true;

        try {
            $this->log("Starting encryption", [
                'project_id' => $project_id,
                'record' => $record,
                'instrument' => $instrument,
                'event_id' => $event_id
            ]);

            $fieldsToEncrypt = $this->getFieldsToEncrypt($project_id);
            if (empty($fieldsToEncrypt)) {
                return;
            }

            // Pull the current record data
            $params = [
                'project_id' => $project_id,
                'return_format' => 'array',
                'records' => [$record],
                'events' => [$event_id]
            ];
            if ($repeat_instance > 1) {
                $params['redcap_repeat_instance'] = $repeat_instance;
            }

            $data = \REDCap::getData($params);
            if (empty($data) || !isset($data[$record][$event_id])) {
                $this->log("Could not fetch record data", [
                    'record' => $record,
                    'event_id' => $event_id,
                    'has_data' => !empty($data),
                    'has_record' => isset($data[$record]),
                    'has_event' => isset($data[$record][$event_id])
                ]);
                return;
            }

            $recordData = $data[$record][$event_id];

            // Handle repeating instruments
            if ($repeat_instance > 1 && isset($recordData['repeat_instances'][$instrument][$repeat_instance])) {
                $recordData = $recordData['repeat_instances'][$instrument][$repeat_instance];
            }

            // Go through each tagged field and encrypt if needed
            $updatedData = [];
            foreach ($fieldsToEncrypt as $fieldName) {
                if (!isset($recordData[$fieldName])) {
                    continue;
                }

                $value = $recordData[$fieldName];

                // Skip if empty or already encrypted
                $alreadyEncrypted = (strpos($value, 'ENC_') === 0 && strpos($value, '@xx.xx') !== false);
                if (empty($value) || $alreadyEncrypted) {
                    continue;
                }

                $updatedData[$fieldName] = $this->encryptValue($value);
            }

            // Save the encrypted values back
            if (!empty($updatedData)) {
                $saveData = [$record => [$event_id => $updatedData]];
                $result = \REDCap::saveData($project_id, 'array', $saveData, 'overwrite');

                if (empty($result['errors'])) {
                    $this->log("Encrypted fields saved", [
                        'record' => $record,
                        'fields' => implode(', ', array_keys($updatedData))
                    ]);

                    \REDCap::logEvent(
                        "Field Encryption Module",
                        "Encrypted fields: " . implode(', ', array_keys($updatedData)),
                        null, $record, null, $project_id
                    );

                    $this->updateParticipantEmail($project_id, $record, $event_id, $updatedData);
                } else {
                    $this->log("Failed to save encrypted data", [
                        'record' => $record,
                        'errors' => json_encode($result['errors'])
                    ]);
                }
            }

        } catch (\Exception $e) {
            $this->log("Encryption error", [
                'record' => $record,
                'error' => $e->getMessage(),
                'file' => $e->getFile(),
                'line' => $e->getLine()
            ]);
        } finally {
            unset(self::$processingRecord[$recordKey]);
        }
    }

    /**
     * Updates the participant table so ASI can find the encrypted email
     */
    private function updateParticipantEmail($project_id, $record, $event_id, $updatedData)
    {
        try {
            // Figure out which field is designated as the participant email
            $sql = "SELECT survey_email_participant_field FROM redcap_projects WHERE project_id = ?";
            $result = $this->query($sql, [$project_id]);

            if (!$result) {
                return;
            }
            $row = $result->fetch_assoc();
            if (empty($row['survey_email_participant_field'])) {
                return;
            }

            $emailFieldName = $row['survey_email_participant_field'];
            if (!isset($updatedData[$emailFieldName])) {
                return;
            }

            // Update all participant records for this record across all events
            $encryptedEmail = $updatedData[$emailFieldName];
            $updateSql = "UPDATE redcap_surveys_participants p
                          INNER JOIN redcap_surveys s ON p.survey_id = s.survey_id
                          INNER JOIN redcap_surveys_response r ON p.participant_id = r.participant_id
                          SET p.participant_email = ?
                          WHERE r.record = ? AND s.project_id = ?";

            $updateResult = $this->query($updateSql, [$encryptedEmail, $record, $project_id]);

            $this->log("Updated participant email", [
                'record' => $record,
                'affected_rows' => $updateResult ? $updateResult->affected_rows : 0
            ]);

        } catch (\Exception $e) {
            $this->log("Error updating participant email", [
                'error' => $e->getMessage()
            ]);
        }
    }

    /**
     * Hook: shows a notice on data entry forms that have encrypted fields
     */
    public function redcap_data_entry_form_top($project_id, $record, $instrument, $event_id, $group_id, $repeat_instance)
    {
        $fieldsToEncrypt = $this->getFieldsToEncrypt($project_id);
        if (!empty($fieldsToEncrypt)) {
            echo "<div style='background-color:#fff3cd;border:1px solid #ffc107;padding:10px;margin:10px 0;border-radius:4px;'>
                <strong>Privacy Notice:</strong> Some fields on this form are encrypted for privacy.
            </div>";
        }
    }

    /**
     * Hook: masks encrypted values on data entry forms
     */
    public function redcap_data_entry_form($project_id, $record, $instrument, $event_id, $group_id, $repeat_instance)
    {
        $this->outputFieldMaskingScript($project_id);
    }

    /**
     * Hook: masks encrypted values on survey pages (for returning participants)
     */
    public function redcap_survey_page($project_id, $record, $instrument, $event_id, $group_id, $survey_hash, $response_id, $repeat_instance)
    {
        // Only mask if there's already a response (not a fresh survey)
        if (!empty($record) && !empty($response_id)) {
            $this->outputFieldMaskingScript($project_id);
        }
    }

    /**
     * Outputs JS that replaces encrypted values with [ENCRYPTED] in the UI
     * Wrapped in IIFE to avoid global scope pollution
     */
    private function outputFieldMaskingScript($project_id)
    {
        $fieldsToEncrypt = $this->getFieldsToEncrypt($project_id);
        if (empty($fieldsToEncrypt)) {
            return;
        }

        // Using JSON_HEX flags to safely embed in HTML and prevent XSS
        $fieldsJson = json_encode($fieldsToEncrypt, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);

        echo "<script type='text/javascript'>
(function() {
    $(document).ready(function() {
        var fieldsToMask = {$fieldsJson};

        fieldsToMask.forEach(function(fieldName) {
            // Escape special chars for jQuery selector
            var escapedFieldName = fieldName.replace(/([!\"#$%&'()*+,.\\/:;<=>?@\\[\\]^`{|}~])/g, '\\\\$1');
            var field = $('input[name=\"' + escapedFieldName + '\"], textarea[name=\"' + escapedFieldName + '\"]');

            if (field.length && field.val()) {
                var currentValue = field.val().toString();

                // Check for our encrypted format
                if (currentValue.indexOf('ENC_') === 0 && currentValue.indexOf('@xx.xx') !== -1) {
                    field.val('[ENCRYPTED]');
                    field.prop('readonly', true);
                    field.prop('disabled', false);
                    field.css({
                        'background-color': '#f0f0f0',
                        'color': '#666',
                        'font-style': 'italic',
                        'cursor': 'not-allowed',
                        'pointer-events': 'none'
                    });

                    // Remove inline handlers that trigger validation popups
                    field.removeAttr('onblur');
                    field.removeAttr('onfocus');
                    field.removeAttr('onclick');

                    // Add overlay to block interaction
                    var wrapper = field.parent();
                    if (!wrapper.hasClass('encrypted-field-wrapper')) {
                        field.wrap('<div class=\"encrypted-field-wrapper\" style=\"position:relative;display:inline-block;width:100%\"></div>');
                        field.after('<div style=\"position:absolute;top:0;left:0;right:0;bottom:0;cursor:not-allowed;z-index:10\"></div>');
                    }

                    // Backup event blocking
                    field.on('focus click mousedown touchstart', function(e) {
                        e.preventDefault();
                        e.stopPropagation();
                        $(this).blur();
                        return false;
                    });
                }
            }
        });
    });
})();
</script>";
    }

    /**
     * Hook: masks encrypted values in reports
     */
    public function redcap_report_data($project_id, $data, $fields, $events, $groups, $records)
    {
        $fieldsToEncrypt = $this->getFieldsToEncrypt($project_id);
        if (empty($fieldsToEncrypt)) {
            return $data;
        }

        foreach ($data as &$row) {
            foreach ($fieldsToEncrypt as $fieldName) {
                if (!empty($row[$fieldName]) && strpos($row[$fieldName], 'ENC_') === 0 && strpos($row[$fieldName], '@xx.xx') !== false) {
                    $row[$fieldName] = '[ENCRYPTED]';
                }
            }
        }
        return $data;
    }

    /**
     * Hook: intercepts outgoing emails to decrypt addresses if needed
     */
    public function redcap_email($to, $from, $subject, $message, $cc, $bcc, $fromName, $attachments)
    {
        try {
            $modified = false;
            $decryptedTo = $to;
            $decryptedCc = $cc;
            $decryptedBcc = $bcc;

            // Check each address field for our encrypted format
            if (!empty($to) && strpos($to, 'ENC_') === 0 && strpos($to, '@xx.xx') !== false) {
                $decryptedTo = $this->decryptValue($to);
                $modified = true;
            }
            if (!empty($cc) && strpos($cc, 'ENC_') === 0 && strpos($cc, '@xx.xx') !== false) {
                $decryptedCc = $this->decryptValue($cc);
                $modified = true;
            }
            if (!empty($bcc) && strpos($bcc, 'ENC_') === 0 && strpos($bcc, '@xx.xx') !== false) {
                $decryptedBcc = $this->decryptValue($bcc);
                $modified = true;
            }

            if ($modified) {
                // Send with decrypted addresses, return false to stop REDCap's send
                \REDCap::email($decryptedTo, $from, $subject, $message, $decryptedCc, $decryptedBcc, $fromName, $attachments);
                $this->log("Email sent via hook", ['subject' => substr($subject, 0, 50)]);
                return false;
            }

        } catch (\Exception $e) {
            $this->log("Email hook error", ['error' => $e->getMessage()]);
        }

        return true;
    }

    /**
     * Copies encrypted emails to participant records that are missing them
     * This handles longitudinal projects where each event has separate participant records
     */
    private function syncMissingParticipantEmails()
    {
        try {
            $sql = "UPDATE redcap_surveys_participants p_empty
                    INNER JOIN redcap_surveys s_empty ON p_empty.survey_id = s_empty.survey_id
                    INNER JOIN redcap_surveys_response r_empty ON p_empty.participant_id = r_empty.participant_id
                    INNER JOIN (
                        SELECT r.record, s.project_id, p.participant_email
                        FROM redcap_surveys_participants p
                        INNER JOIN redcap_surveys s ON p.survey_id = s.survey_id
                        INNER JOIN redcap_surveys_response r ON p.participant_id = r.participant_id
                        WHERE p.participant_email LIKE 'ENC_%@xx.xx'
                        GROUP BY r.record, s.project_id
                    ) AS email_source
                    ON r_empty.record = email_source.record AND s_empty.project_id = email_source.project_id
                    SET p_empty.participant_email = email_source.participant_email
                    WHERE (p_empty.participant_email IS NULL OR p_empty.participant_email = '')";

            $result = $this->query($sql, []);

            if ($result && $result->affected_rows > 0) {
                $this->log("Synced participant emails", ['affected_rows' => $result->affected_rows]);
            }

        } catch (\Exception $e) {
            $this->log("Error syncing participant emails", ['error' => $e->getMessage()]);
        }
    }

    /**
     * Cron: processes queued survey invitations that have encrypted emails
     * Runs every 30 seconds. Also picks up invitations that failed because
     * REDCap tried to send to the fake ENC_...@xx.xx address.
     */
    public function processScheduledSurveyInvitations()
    {
        try {
            // First make sure all participant records have the encrypted email
            $this->syncMissingParticipantEmails();

            // Find invitations ready to send with encrypted addresses
            $sql = "SELECT ssq.ssq_id, ssq.record, er.participant_id, p.participant_email, p.hash,
                           surv.survey_id, surv.project_id, surv.form_name,
                           ss.email_subject, ss.email_content, ss.email_sender
                    FROM redcap_surveys_scheduler_queue ssq
                    INNER JOIN redcap_surveys_emails_recipients er ON ssq.email_recip_id = er.email_recip_id
                    INNER JOIN redcap_surveys_participants p ON er.participant_id = p.participant_id
                    INNER JOIN redcap_surveys_scheduler ss ON ssq.ss_id = ss.ss_id
                    INNER JOIN redcap_surveys surv ON ss.survey_id = surv.survey_id
                    WHERE ssq.scheduled_time_to_send <= NOW()
                    AND (ssq.status = 'QUEUED' OR (ssq.status = 'DID NOT SEND' AND ssq.reason_not_sent = 'EMAIL ATTEMPT FAILED'))
                    AND p.participant_email LIKE 'ENC_%@xx.xx'
                    ORDER BY ssq.scheduled_time_to_send ASC
                    LIMIT 200";

            $result = $this->query($sql, []);
            if (!$result || !is_object($result)) {
                return;
            }

            $sentCount = 0;
            $failedCount = 0;

            while ($row = $result->fetch_assoc()) {
                try {
                    $decryptedEmail = $this->decryptValue($row['participant_email']);
                    if (!$decryptedEmail || $decryptedEmail === $row['participant_email']) {
                        throw new \Exception("Decryption failed");
                    }

                    // Set up project context
                    $_GET['pid'] = $row['project_id'];
                    if (!defined('PROJECT_ID')) {
                        define('PROJECT_ID', $row['project_id']);
                    }

                    // Build the survey link
                    $surveyLink = APP_PATH_SURVEY_FULL . "?s=" . $row['hash'];

                    $emailSubject = $row['email_subject'] ?: "Survey Invitation";
                    $emailContent = $row['email_content'] ?: "Please complete the survey: " . $surveyLink;
                    $emailSender = $row['email_sender'] ?: "noreply@" . ($_SERVER['SERVER_NAME'] ?? 'localhost');

                    // Replace placeholders - escape the link for safety
                    $escapedLink = \REDCap::escapeHtml($surveyLink);
                    $emailContent = str_replace('[survey-link]', '<a href="' . $escapedLink . '">Survey Link</a>', $emailContent);
                    $emailContent = str_replace('[survey-url]', $escapedLink, $emailContent);

                    $emailSent = \REDCap::email($decryptedEmail, $emailSender, $emailSubject, $emailContent, '', '', '', [], $row['project_id']);

                    if ($emailSent) {
                        $this->query(
                            "UPDATE redcap_surveys_scheduler_queue SET status = 'SENT', time_sent = NOW(), reason_not_sent = NULL WHERE ssq_id = ?",
                            [$row['ssq_id']]
                        );
                        $sentCount++;
                    } else {
                        throw new \Exception("REDCap::email returned false");
                    }

                } catch (\Exception $e) {
                    $this->query(
                        "UPDATE redcap_surveys_scheduler_queue SET status = 'DID NOT SEND', reason_not_sent = 'EMAIL ATTEMPT FAILED' WHERE ssq_id = ?",
                        [$row['ssq_id']]
                    );
                    $this->log("Cron: invitation failed", [
                        'ssq_id' => $row['ssq_id'],
                        'record' => $row['record'],
                        'error' => $e->getMessage()
                    ]);
                    $failedCount++;
                }
            }

            if ($sentCount > 0 || $failedCount > 0) {
                $this->log("Cron completed", ['sent' => $sentCount, 'failed' => $failedCount]);
            }

        } catch (\Exception $e) {
            $this->log("Cron error", ['error' => $e->getMessage()]);
        }
    }
}
