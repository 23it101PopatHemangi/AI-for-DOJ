class LegalQASystem {
    constructor() {
        this.qaDatabase = new Map([
            ["1. Ministry of Law & Justice", 
                "The Ministry of Law & Justice is responsible for the administration of justice, legal affairs, and legislative activities in the United States."],
            
            ["2. What are the main responsibilities of the DOJ?",
                "The main responsibilities of the DOJ include:\n" +
                "1. Enforcing federal laws\n" +
                "2. Investigating and prosecuting crimes\n" +
                "3. Representing the government in court\n" +
                "4. Protecting civil rights\n" +
                "5. Managing federal prisons"],

            ["3. What is the Department of Justice (DOJ)?",
                "What is the Department of Justice: Key Functions include:\n" +
                "1. Appointment of Supreme Court/High Court judges\n" +
                "2. Court infrastructure\n" +
                "3. Legal reforms\n" +
                "4. Access to justice\n" +
                "5. Judicial administration\n" +
                "6. E-Courts project\n" +
                "Visit: https://doj.gov.in/"],

            ["4.Legislative Department",
                    "The Legislative Department is responsible for the following functions:\n" +
                    "1. Drafting and reviewing legislation\n" +
                    "2. Providing legal advice to government departments\n" +
                    "3. Representing the government in court\n" +
                    "4. Managing government litigation"],
            ["5.District Courts in India",
                        "The District Courts in India are the following:\n" +
                        "1. District Courts of various states\n" +
                        "2. Sessions Courts of various states\n" +
                        "3. Family Courts of various states\n" +
                        "4. Small Causes Courts of various states\n" +
                        "5. Metropolitan Magistrate Courts of various states"],
            ["6.Consumer Rights in India",
                "The Consumer Rights in India are the following:\n" +
                "1. E-Daakhil Portal\n" +
                "2. Consumer Helpline\n" +
                "3. Consumer Protection Act\n" +
                "4. Consumer Protection Act\n" +
                "5. Consumer Protection Act"],
            ["7.Legal Aid in India",
                "The Legal Aid in India is the following:\n" +
                "1. NALSA (National Legal Services Authority)\n" +
                "2. Toll-free: 1516\n" +
                "3. Website: nalsa.gov.in"],
            ["8.Cyber Crime Reporting",
                    "The Cyber Crime Reporting is the following:\n" +
                    "1. Cyber Crime Reporting\n" +
                    "2. Cyber Crime Reporting\n" +
                    "3. Cyber Crime Reporting\n" +
                    "4. Cyber Crime Reporting\n" +
                    "5. Cyber Crime Reporting"],
            ["9.Labour Laws in India",
                "The Labour Laws in India are the following:\n" +
                "1. Labour Laws in India\n" +
                "2. Labour Laws in India\n" +
                "3. Labour Laws in India\n" +
                "4. Labour Laws in India\n" +
                "5. Labour Laws in India"],
            ["10.Family Laws in India",
                "The Family Laws in India are the following:\n" +
                "1. Family Laws in India\n" +
                "2. Family Laws in India\n" +
                "3. Family Laws in India\n" +
                "4. Family Laws in India\n" +
                "5. Family Laws in India"]     
        ]);
    }

    getAnswer(question) {
        // First try exact match
        let answer = this.qaDatabase.get(question);
        
        // If no exact match, try without spaces
        if (!answer) {
            const noSpaceQuestion = question.replace(/\s+/g, '');
            for (let [key, value] of this.qaDatabase.entries()) {
                if (key.replace(/\s+/g, '') === noSpaceQuestion) {
                    answer = value;
                    break;
                }
            }
        }
        
        // If still no match, try by number
        if (!answer) {
            const questionNumber = question.split('.')[0];
            for (let [key, value] of this.qaDatabase.entries()) {
                if (key.startsWith(questionNumber + '.') || 
                    key.startsWith(questionNumber + ' .') || 
                    key.startsWith(questionNumber + 'Who') ||
                    key.startsWith(questionNumber + 'Department')) {
                    answer = value;
                    break;
                }
            }
        }
        
        return answer || "Please specify what information you need about these topics. For official information, visit: https://www.justice.gov/";
    }
}

// Create instance
const qaSystem = new LegalQASystem();

// Function to handle questions
function handleQuestion(question) {
    const answer = qaSystem.getAnswer(question);
    console.log(answer);
    return answer;
}

// Add event listener for the input
document.addEventListener('DOMContentLoaded', () => {
    const input = document.getElementById('questionInput');
    const answerDiv = document.getElementById('answer');

    function displayAnswer() {
        const question = input.value;
        const answer = qaSystem.getAnswer(question);
        answerDiv.textContent = answer;
    }

    // Handle button click
    document.querySelector('button').addEventListener('click', displayAnswer);

    // Handle Enter key
    input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            displayAnswer();
        }
    });
});