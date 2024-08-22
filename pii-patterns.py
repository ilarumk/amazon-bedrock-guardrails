client.create_guardrail(
    name='custom-pii-protection',
    description='Prevents the model from exposing or processing personal identifiable information (PII) using custom patterns.',
    sensitiveInformationPolicyConfig={
        'piiEntitiesConfig': [
            {'type': 'EMAIL', 'action': 'ANONYMIZE'},
            {'type': 'PHONE', 'action': 'ANONYMIZE'},
            {'type': 'NAME', 'action': 'ANONYMIZE'},
            {'type': 'US_SOCIAL_SECURITY_NUMBER', 'action': 'BLOCK'},
            {'type': 'US_BANK_ACCOUNT_NUMBER', 'action': 'BLOCK'},
            {'type': 'CREDIT_DEBIT_CARD_NUMBER', 'action': 'BLOCK'}
        ],
        'regexesConfig': [
            {
                'name': 'Custom PII - Passport Number',
                'description': 'Matches passport numbers in the format X1234567 or 12345678',
                'pattern': r'\b[A-Z]\d{7}\b|\b\d{8}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Driver License',
                'description': 'Matches driver license numbers in the format A1234567',
                'pattern': r'\b[A-Z]\d{7}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - National ID',
                'description': 'Matches national ID numbers, e.g., UK, India',
                'pattern': r'\b\d{10,12}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Health Insurance Number',
                'description': 'Matches health insurance numbers in various formats',
                'pattern': r'\b\d{9}\b|\b[A-Z0-9]{12}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Student ID',
                'description': 'Matches student ID numbers',
                'pattern': r'\b\d{7,10}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Tax ID',
                'description': 'Matches tax identification numbers, e.g., EIN, TIN',
                'pattern': r'\b\d{9}\b|\b[A-Z]{2}\d{7}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Bank Routing Number',
                'description': 'Matches bank routing numbers in the format 123456789',
                'pattern': r'\b\d{9}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Birth Certificate Number',
                'description': 'Matches birth certificate numbers in various formats',
                'pattern': r'\b[A-Z0-9]{8,12}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Military ID',
                'description': 'Matches military ID numbers',
                'pattern': r'\b[A-Z0-9]{10}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Vehicle Registration',
                'description': 'Matches vehicle registration numbers in various formats',
                'pattern': r'\b[A-Z0-9]{1,3}-\d{1,4}-[A-Z]{1,2}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - License Plate Number',
                'description': 'Matches license plate numbers',
                'pattern': r'\b[A-Z0-9]{2,7}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Insurance Policy Number',
                'description': 'Matches insurance policy numbers in various formats',
                'pattern': r'\b[A-Z0-9]{10,15}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Bank Account Number',
                'description': 'Matches bank account numbers',
                'pattern': r'\b\d{10,12}\b',
                'action': 'BLOCK'
            },
            {
                'name': 'Custom PII - Credit Card CVV',
                'description': 'Matches credit card CVV codes',
                'pattern': r'\b\d{3,4}\b',
                'action': 'BLOCK'
            },
            {
                'name': 'Custom PII - Foreign Passport Number',
                'description': 'Matches foreign passport numbers',
                'pattern': r'\b[A-Z0-9]{8,9}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Visa Number',
                'description': 'Matches visa numbers',
                'pattern': r'\b[A-Z0-9]{8,9}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Residential Address',
                'description': 'Matches residential addresses',
                'pattern': r'\d+\s[A-Za-z]+\s[A-Za-z]+',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - IP Address',
                'description': 'Matches IPv4 addresses',
                'pattern': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
                'action': 'BLOCK'
            },
            {
                'name': 'Custom PII - MAC Address',
                'description': 'Matches MAC addresses',
                'pattern': r'\b[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}\b',
                'action': 'BLOCK'
            },
            {
                'name': 'Custom PII - Social Media Handle',
                'description': 'Matches social media handles',
                'pattern': r'@[A-Za-z0-9_]+',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - IMEI Number',
                'description': 'Matches IMEI numbers',
                'pattern': r'\b\d{15}\b',
                'action': 'BLOCK'
            },
            {
                'name': 'Custom PII - Passport Country Code',
                'description': 'Matches passport country codes',
                'pattern': r'\b[A-Z]{3}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - School ID Number',
                'description': 'Matches school ID numbers',
                'pattern': r'\b\d{7}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Employee ID Number',
                'description': 'Matches employee ID numbers',
                'pattern': r'\b[A-Z0-9]{6}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Health Record Number',
                'description': 'Matches health record numbers',
                'pattern': r'\b\d{9}\b|\b[A-Z0-9]{12}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Retirement Account Number',
                'description': 'Matches retirement account numbers',
                'pattern': r'\b\d{9}\b|\b[A-Z0-9]{10}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Pension Number',
                'description': 'Matches pension account numbers',
                'pattern': r'\b\d{9}\b|\b[A-Z0-9]{10}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Financial Account Number',
                'description': 'Matches financial account numbers',
                'pattern': r'\b\d{9}\b|\b[A-Z0-9]{10}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Medical Record ID',
                'description': 'Matches medical record IDs',
                'pattern': r'\b[A-Z0-9]{12}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Property ID',
                'description': 'Matches property identification numbers',
                'pattern': r'\b\d{12}\b|\b[A-Z0-9]{12}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Immigration Number',
                'description': 'Matches immigration numbers',
                'pattern': r'\b[A-Z0-9]{9}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Criminal Record Number',
                'description': 'Matches criminal record numbers',
                'pattern': r'\b[A-Z0-9]{9}\b',
                'action': 'BLOCK'
            },
            {
                'name': 'Custom PII - Refugee ID',
                'description': 'Matches refugee ID numbers',
                'pattern': r'\b[A-Z0-9]{12}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Diplomatic ID',
                'description': 'Matches diplomatic ID numbers',
                'pattern': r'\b[A-Z0-9]{8}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Government ID Number',
                'description': 'Matches government ID numbers',
                'pattern': r'\b[A-Z0-9]{9}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Court Case Number',
                'description': 'Matches court case numbers',
                'pattern': r'\b[A-Z0-9]{9}\b',
                'action': 'BLOCK'
            },
            {
                'name': 'Custom PII - Voting ID Number',
                'description': 'Matches voting ID numbers',
                'pattern': r'\b[A-Z0-9]{9}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - SSN (Non-US)',
                'description': 'Matches non-US social security numbers',
                'pattern': r'\b\d{9}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Inmate ID',
                'description': 'Matches inmate identification numbers',
                'pattern': r'\b[A-Z0-9]{9}\b',
                'action': 'BLOCK'
            },
            {
                'name': 'Custom PII - Pension Fund ID',
                'description': 'Matches pension fund ID numbers',
                'pattern': r'\b[A-Z0-9]{10}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Merchant Account ID',
                'description': 'Matches merchant account ID numbers',
                'pattern': r'\b[A-Z0-9]{12}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Medicare Number',
                'description': 'Matches Medicare numbers',
                'pattern': r'\b[A-Z0-9]{10}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Medicaid Number',
                'description': 'Matches Medicaid numbers',
                'pattern': r'\b[A-Z0-9]{10}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - National Health ID',
                'description': 'Matches national health ID numbers',
                'pattern': r'\b[A-Z0-9]{12}\b',
                'action': 'ANONYMIZE'
            },
            {
                'name': 'Custom PII - Foreign Identity Number',
                'description': 'Matches foreign identity numbers',
                'pattern': r'\b[A-Z0-9]{12}\b',
                'action': 'ANONYMIZE'
            }
        ]
    },
    blockedInputMessaging="""For your safety, please avoid sharing personal identifiable information (PII) like passport numbers or driver’s license numbers. If you need assistance, please contact our support team directly.""",
    blockedOutputsMessaging="""For your safety, please avoid sharing personal identifiable information (PII) like passport numbers or driver’s license numbers. If you need assistance, please contact our support team directly.""",
    tags=[
        {'key': 'purpose', 'value': 'custom-pii-protection'},
        {'key': 'environment', 'value': 'production'}
    ]
)
