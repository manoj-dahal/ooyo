<?php
// Auth0 API Handler for Backend Authentication

// Set headers for JSON responses
header('Content-Type: application/json');

// Auth0 configuration - replace with your actual Auth0 credentials
$auth0Config = [
    'domain' => 'YOUR_AUTH0_DOMAIN',
    'clientId' => 'YOUR_AUTH0_CLIENT_ID',
    'clientSecret' => 'YOUR_AUTH0_CLIENT_SECRET',
    'audience' => 'https://YOUR_AUTH0_DOMAIN/api/v2/',
    'redirectUri' => 'http://localhost/callback',  // Update with your actual callback URL
];

// Function to validate JWT token
function validateToken($token) {
    global $auth0Config;
    
    // In a production environment, you should use a proper JWT library
    // This is a simplified example
    
    // Decode token parts
    $tokenParts = explode('.', $token);
    if (count($tokenParts) != 3) {
        return false;
    }
    
    // Get payload
    $payload = json_decode(base64_decode(str_replace(
        ['-', '_'], 
        ['+', '/'], 
        $tokenParts[1]
    )), true);
    
    // Check if token is expired
    if (!isset($payload['exp']) || $payload['exp'] < time()) {
        return false;
    }
    
    // Check issuer
    if (!isset($payload['iss']) || $payload['iss'] !== 'https://' . $auth0Config['domain'] . '/') {
        return false;
    }
    
    // Check audience
    if (!isset($payload['aud']) || $payload['aud'] !== $auth0Config['clientId']) {
        return false;
    }
    
    return $payload;
}

// Get the authorization header
function getAuthorizationHeader() {
    $headers = null;
    
    if (isset($_SERVER['Authorization'])) {
        $headers = trim($_SERVER['Authorization']);
    } elseif (isset($_SERVER['HTTP_AUTHORIZATION'])) {
        $headers = trim($_SERVER['HTTP_AUTHORIZATION']);
    } elseif (function_exists('apache_request_headers')) {
        $requestHeaders = apache_request_headers();
        if (isset($requestHeaders['Authorization'])) {
            $headers = trim($requestHeaders['Authorization']);
        }
    }
    
    return $headers;
}

// Get the bearer token
function getBearerToken() {
    $headers = getAuthorizationHeader();
    
    if (!empty($headers)) {
        if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
            return $matches[1];
        }
    }
    
    return null;
}

// Handle API requests
$requestMethod = $_SERVER['REQUEST_METHOD'];
$endpoint = isset($_GET['endpoint']) ? $_GET['endpoint'] : '';

// Protected endpoints require authentication
$protectedEndpoints = ['user-data', 'protected-content'];

// Check if endpoint requires authentication
if (in_array($endpoint, $protectedEndpoints)) {
    $token = getBearerToken();
    
    if (!$token) {
        http_response_code(401);
        echo json_encode(['error' => 'No token provided']);
        exit;
    }
    
    $payload = validateToken($token);
    
    if (!$payload) {
        http_response_code(401);
        echo json_encode(['error' => 'Invalid token']);
        exit;
    }
    
    // Token is valid, proceed with the request
    switch ($endpoint) {
        case 'user-data':
            // Return user data from the token
            echo json_encode([
                'success' => true,
                'user' => [
                    'sub' => $payload['sub'],
                    'name' => $payload['name'] ?? '',
                    'email' => $payload['email'] ?? '',
                    'picture' => $payload['picture'] ?? ''
                ]
            ]);
            break;
            
        case 'protected-content':
            // Return protected content
            echo json_encode([
                'success' => true,
                'content' => 'This is protected content only visible to authenticated users.'
            ]);
            break;
            
        default:
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
            break;
    }
} else {
    // Public endpoints
    switch ($endpoint) {
        case 'public-data':
            // Return public data
            echo json_encode([
                'success' => true,
                'message' => 'This is public data accessible to anyone.'
            ]);
            break;
            
        default:
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
            break;
    }
}