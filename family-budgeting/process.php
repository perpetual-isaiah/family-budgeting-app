<?php
// Include database configuration
include 'config.php';

// Check if the request method is POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Retrieve form data
    $name = isset($_POST['name']) ? $_POST['name'] : '';
    $email = $_POST['email'];
    $password = $_POST['password'];
    
    // Check which form is being submitted
    if (!empty($name)) {
        // Sign up logic
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        
        // Prepare statement for signup
        $stmt = $db->prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)");

        
        if ($stmt) {
            $stmt->bind_param("sss", $name, $email, $hashedPassword);
            
            if ($stmt->execute()) {
                // Redirect to login page after successful sign-up
                header("Location: login.html");
                exit();
            } else {
                echo "Error: " . $stmt->error;
            }
            
            // Close the statement
            $stmt->close();
        } else {
            echo "Error preparing statement: " . $db->error;
        }
    } else {
        // Sign in logic
        $stmt = $db->prepare("SELECT password FROM users WHERE email = ?");
        
        if ($stmt) {
            $stmt->bind_param("s", $email);
            
            if ($stmt->execute()) {
                $stmt->store_result();
                
                if ($stmt->num_rows > 0) {
                    $stmt->bind_result($hashedPassword);
                    $stmt->fetch();
                    
                    // Verify the password
                    if (password_verify($password, $hashedPassword)) {
                        echo "Sign in successful.";
                    } else {
                        echo "Invalid password.";
                    }
                } else {
                    echo "No user found with this email.";
                }
            } else {
                echo "Error: " . $stmt->error;
            }
            
            // Close the statement
            $stmt->close();
        } else {
            echo "Error preparing statement: " . $db->error;
        }
    }
} else {
    echo "Invalid request method.";
}

// Close the database connection at the end of the script
$db->close();
?>
