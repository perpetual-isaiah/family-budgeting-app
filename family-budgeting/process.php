<?php
// Start session
session_start();

// Include database configuration
include 'config.php';

// Set default response to an error message
$response = ['status' => 'error', 'message' => 'An unexpected error occurred.'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Determine whether it's sign-up or sign-in
    if (isset($_POST['name']) && !empty($_POST['name'])) {
        // Handle Sign Up
        $name = $_POST['name'];
        $email = $_POST['email'];
        $password = $_POST['password'];

        // Check if the email already exists
        $stmt = $db->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $response = ['status' => 'error', 'message' => 'Email is already registered.'];
        } else {
            // Hash the password before storing it
            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

            // Insert new user into the database
            $stmt = $db->prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)");
            $stmt->bind_param("sss", $name, $email, $hashedPassword);

            if ($stmt->execute()) {
                $response = ['status' => 'success', 'message' => 'Account created successfully!'];
            } else {
                $response = ['status' => 'error', 'message' => 'Error: ' . $stmt->error];
            }
        }

    } else {
        // Handle Sign In
        $email = $_POST['email'];
        $password = $_POST['password'];

        // Fetch user data from the database
        $stmt = $db->prepare("SELECT id, name, password FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $stmt->bind_result($userId, $userName, $hashedPassword);
            $stmt->fetch();

            // Verify the password
            if (password_verify($password, $hashedPassword)) {
                // Set session variables
                $_SESSION['user_id'] = $userId;
                $_SESSION['user_name'] = $userName;
                $_SESSION['user_email'] = $email;

                $response = ['status' => 'success', 'message' => 'Login successful!'];
            } else {
                $response = ['status' => 'error', 'message' => 'Invalid email or password.'];
            }
        } else {
            $response = ['status' => 'error', 'message' => 'No user found with this email.'];
        }
    }
} else {
    $response = ['status' => 'error', 'message' => 'Invalid request method.'];
}

// Return the response as JSON
header('Content-Type: application/json');
echo json_encode($response);

// Close the database connection
$db->close();
?>
