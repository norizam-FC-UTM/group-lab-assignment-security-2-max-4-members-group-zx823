<?php
// ==========================================================
// SECJ3483 Web Technology
// Person BMI Insecure Slim Backend Starter
// ==========================================================
// NOTA:
// This backend is intentionally insecure.
// provided for investigation and fixing during lab activiy this week.
// Do NOT use this code in real applications.
// ==========================================================

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../src/db.php';

$app = AppFactory::create();

// Required for JSON/form body parsing in Slim 4.
$app->addBodyParsingMiddleware();

// Helpful for development error display.
// INSECURE: In production, detailed errors should not be shown to users.
$app->addErrorMiddleware(true, true, true);

// ----------------------------------------------------------
// CORS for Vue CLI frontend
// ----------------------------------------------------------
$app->add(function (Request $request, $handler) {
    if ($request->getMethod() === 'OPTIONS') {
        $response = new \Slim\Psr7\Response();
    } else {
        $response = $handler->handle($request);
    }

    return $response
        ->withHeader('Access-Control-Allow-Origin', '*') // INSECURE: convenient untuk aktiviti lab, tidak untuk production.
        ->withHeader('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type, Accept, Origin, Authorization')
        ->withHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        ->withHeader('Access-Control-Allow-Credentials', 'false');
});

// ----------------------------------------------------------
// Helper functions
// ----------------------------------------------------------
function jsonResponse(Response $response, $data, int $status = 200): Response
{
    $response->getBody()->write(json_encode($data, JSON_PRETTY_PRINT));

    return $response
        ->withHeader('Content-Type', 'application/json')
        ->withStatus($status);
}

function removeSensitiveFields(?array $data): ?array
{
    if (!$data) {
        return null;
    }

    unset($data['password'], $data['password_hash']);

    return $data;
}

function publicUser(?array $user): ?array
{
    return removeSensitiveFields($user);
}

//
function getRequestData(Request $request): array
{
    $data = $request->getParsedBody();

    if (is_array($data) && !empty($data)) {
        return $data;
    }

    $rawBody = (string) $request->getBody();

    if ($rawBody !== '') {
        $jsonData = json_decode($rawBody, true);

        if (is_array($jsonData)) {
            return $jsonData;
        }
    }

    return is_array($data) ? $data : [];
}

// INSECURE: This is NOT a real JWT.
// This is just base64 JSON. You should replace this with real signed JWT sebagai pembaikan.
function createFakeToken(array $user): string
{
    $payload = [
        'user_id' => $user['id'],
        'role' => $user['role'],
        'email' => $user['email'],
        'note' => 'INSECURE_FAKE_TOKEN_NO_SIGNATURE_NO_EXPIRY'
    ];

    return base64_encode(json_encode($payload));
}

// INSECURE: This trusts an unsigned, editable token.
// You should replace this with proper JWT verification.
function getFakeUserFromToken(Request $request): ?array
{
    $auth = $request->getHeaderLine('Authorization');

    if (!$auth || !preg_match('/Bearer\s+(\S+)/', $auth, $matches)) {
        return null;
    }
    $json = base64_decode($matches[1], true);

    if (!$json) {
        return null;
    }
    $payload = json_decode($json, true);
    return is_array($payload) ? $payload : null;
}

function getRequiredUserFromToken(Request $request, Response $response): array|Response
{
    $fakeUser = getFakeUserFromToken($request);

    if (!$fakeUser || empty($fakeUser['user_id'])) {
        return jsonResponse($response, [
            'error' => 'Authentication required'
        ], 401);
    }

    return $fakeUser;
}

function bmiCategory(float $bmi): string
{
    if ($bmi < 18.5) {
        return 'Underweight';
    }

    if ($bmi < 25) {
        return 'Normal';
    }

    if ($bmi < 30) {
        return 'Overweight';
    }

    return 'Obese';
}

function exposeException(Response $response, Throwable $e): Response
{
    // INSECURE: exposes detailed internal error to API client.
    return jsonResponse($response, [
        'error' => $e->getMessage(),
        'file' => $e->getFile(),
        'line' => $e->getLine()
    ], 500);
}

function calculateBmi(float $height, float $weight): float
{
    return round($weight / ($height * $height), 2);
}

function getBmiCategory(float $bmi): string
{
    if ($bmi < 18.5) {
        return 'Underweight';
    }

    if ($bmi < 25) {
        return 'Normal';
    }

    if ($bmi < 30) {
        return 'Overweight';
    }

    return 'Obese';
}

// ----------------------------------------------------------
// Root routes 
// ----------------------------------------------------------
$app->get('/', function (Request $request, Response $response) {
    return jsonResponse($response, [
        'message' => 'Person BMI Insecure Slim Backend Starter',
        'warning' => 'This backend is intentionally insecure for classroom investigation.'
    ]);
});

$app->get('/api/health', function (Request $request, Response $response) {
    return jsonResponse($response, [
        'status' => 'ok',
        'api' => 'person-bmi-insecure-backend'
    ]);
});

// ----------------------------------------------------------
// Public route: Register
// ----------------------------------------------------------
$app->post('/api/register', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();
        $data = getRequestData($request);

        // INSECURE:
        // - No backend validation.
        // - Role is accepted from frontend, so user can register as admin/staff.
        // - Password is stored as plain text.
        // - password_hash is intentionally filled with the same plain password for investigation.
        $name = $data['name'] ?? '';
        $email = $data['email'] ?? '';
        $password = $data['password'] ?? '';
        $role = $data['role'] ?? 'user';

        $sql = "INSERT INTO users (name, email, password, password_hash, role)
                VALUES ('$name', '$email', '$password', '$password', '$role')";

        // INSECURE: direct SQL execution with user input.
        $pdo->exec($sql);
        $id = $pdo->lastInsertId();

        $stmt = $pdo->prepare("SELECT id, name, email, role, created_at FROM users WHERE id = :id");
        $stmt->execute([':id' => $id]);
        $user = $stmt->fetch();

        return jsonResponse($response, [
            'message' => 'User registered.',
            'user' => publicUser($user),
            'debug_received_body' => removeSensitiveFields($data)
        ], 201);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

// ----------------------------------------------------------
// Public route: Login
// ----------------------------------------------------------
$app->post('/api/login', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();
        $data = getRequestData($request);

        $email = $data['email'] ?? '';
        $password = $data['password'] ?? '';

        $sql = "SELECT id, name, email, role, created_at
                FROM users
                WHERE email = :email AND password = :password
                LIMIT 1";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            ':email' => $email,
            ':password' => $password
        ]);
        $user = $stmt->fetch();

        if (!$user) {
            return jsonResponse($response, [
                'error' => 'Invalid login',
                'debug_received_body' => removeSensitiveFields($data)
            ], 401);
        }

        // INSECURE: fake unsigned token with no expiry.
        $token = createFakeToken($user);

        return jsonResponse($response, [
            'message' => 'Login successful.',
            'token' => $token,
            'user' => publicUser($user),
            'debug_received_body' => removeSensitiveFields($data)
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

// ----------------------------------------------------------
// Protected-ish route: Profile
// ----------------------------------------------------------
$app->get('/api/profile', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();

        // INSECURE:
        // If token missing, defaults to user 1.
        // If token exists, trusts unsigned editable token.
        $fakeUser = getFakeUserFromToken($request);
        $userId = $fakeUser['user_id'] ?? 1;

        $stmt = $pdo->prepare("SELECT id, name, email, role, created_at FROM users WHERE id = :id");
        $stmt->execute([':id' => $userId]);
        $user = $stmt->fetch();

        return jsonResponse($response, [
            'message' => 'Profile returned. This route trusts insecure token/default user.',
            'user' => $user,
            'token_payload_trusted_by_backend' => $fakeUser
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

// ----------------------------------------------------------
// BMI routes
// ----------------------------------------------------------
$app->get('/api/persons', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();

        // INSECURE:
        // Trusts unsigned token. If no token, returns all records.
        // Also accepts ?user_id= to override owner.
        $fakeUser = getFakeUserFromToken($request);
        $params = $request->getQueryParams();
        $userId = $params['user_id'] ?? ($fakeUser['user_id'] ?? null);

        if ($userId) {
            $sql = "SELECT * FROM persons WHERE user_id = $userId ORDER BY id DESC";
        } else {
            $sql = "SELECT * FROM persons ORDER BY id DESC";
        }

        $persons = $pdo->query($sql)->fetchAll();

        return jsonResponse($response, [
            'message' => 'BMI records returned. This route is intentionally weak.',
            'persons' => $persons,
            'debug_sql' => $sql
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

$app->post('/api/persons', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();
        $data = getRequestData($request);

        $fakeUser = getRequiredUserFromToken($request, $response);
        if ($fakeUser instanceof Response) {
            return $fakeUser;
        }

        $name = trim((string) ($data['name'] ?? ''));
        $age = $data['age'] ?? null;
        $height = $data['height'] ?? null;
        $weight = $data['weight'] ?? null;
        $notes = trim((string) ($data['notes'] ?? ''));

        $errors = [];

        if ($name === '') {
            $errors['name'] = 'Name is required.';
        }

        if (!is_numeric($age) || (int) $age < 1 || (int) $age > 120) {
            $errors['age'] = 'Age must be between 1 and 120.';
        }

        if (!is_numeric($height) || (float) $height < 0.5 || (float) $height > 2.5) {
            $errors['height'] = 'Height must be between 0.5 and 2.5 meters.';
        }

        if (!is_numeric($weight) || (float) $weight < 2 || (float) $weight > 300) {
            $errors['weight'] = 'Weight must be between 2 and 300 kg.';
        }

        if ($errors) {
            return jsonResponse($response, [
                'error' => 'Invalid BMI data',
                'validation_errors' => $errors
            ], 400);
        }

        $age = (int) $age;
        $height = (float) $height;
        $weight = (float) $weight;
        $bmi = round($weight / ($height * $height), 2);
        $category = bmiCategory($bmi);
        $user_id = (int) $fakeUser['user_id'];

        $stmt = $pdo->prepare(
            "INSERT INTO persons (user_id, name, age, height, weight, bmi, category, notes)
             VALUES (:user_id, :name, :age, :height, :weight, :bmi, :category, :notes)"
        );
        $stmt->execute([
            ':user_id' => $user_id,
            ':name' => $name,
            ':age' => $age,
            ':height' => $height,
            ':weight' => $weight,
            ':bmi' => $bmi,
            ':category' => $category,
            ':notes' => $notes
        ]);
        $id = $pdo->lastInsertId();

        $stmt = $pdo->prepare("SELECT * FROM persons WHERE id = :id");
        $stmt->execute([':id' => $id]);
        $person = $stmt->fetch();

        return jsonResponse($response, [
            'message' => 'BMI record created after backend validation.',
            'person' => $person,
            'debug_received_body' => $data
        ], 201);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

$app->get('/api/persons/{id}', function (Request $request, Response $response, array $args) {
    try {
        $pdo = getPDO();
        $id = (int) $args['id'];

        $fakeUser = getRequiredUserFromToken($request, $response);
        if ($fakeUser instanceof Response) {
            return $fakeUser;
        }

        $userId = (int) $fakeUser['user_id'];
        $role = $fakeUser['role'] ?? 'user';

        $stmt = $pdo->prepare("SELECT * FROM persons WHERE id = :id");
        $stmt->execute([':id' => $id]);
        $person = $stmt->fetch();

        if (!$person) {
            return jsonResponse($response, ['error' => 'Record not found'], 404);
        }

        $canAccess = (int) $person['user_id'] === $userId || in_array($role, ['staff', 'admin'], true);

        if (!$canAccess) {
            return jsonResponse($response, [
                'error' => 'Access denied'
            ], 403);
        }

        return jsonResponse($response, [
            'message' => 'Record returned after ownership/role check.',
            'person' => $person
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

$app->put('/api/persons/{id}', function (Request $request, Response $response, array $args) {
    try {
        $pdo = getPDO();
        $id = $args['id'];
        $data = getRequestData($request);

        $allowedFields = ['name', 'age', 'height', 'weight', 'notes'];
        $cleanData = [];

        foreach ($allowedFields as $field) {
            if (array_key_exists($field, $data)) {
                $cleanData[$field] = $data[$field];
            }
        }

        if (array_key_exists('height', $cleanData) || array_key_exists('weight', $cleanData)) {
            $currentPerson = $pdo->query("SELECT * FROM persons WHERE id = $id")->fetch();
            $height = array_key_exists('height', $cleanData)
                ? (float) $cleanData['height']
                : (float) ($currentPerson['height'] ?? 0);
            $weight = array_key_exists('weight', $cleanData)
                ? (float) $cleanData['weight']
                : (float) ($currentPerson['weight'] ?? 0);

            if ($height > 0 && $weight > 0) {
                $bmi = calculateBmi($height, $weight);
                $cleanData['bmi'] = $bmi;
                $cleanData['category'] = getBmiCategory($bmi);
            }
        }

        $sets = [];

        foreach ($cleanData as $field => $value) {
            if (is_numeric($value)) {
                $sets[] = "$field = $value";
            } else {
                $escaped = str_replace("'", "''", (string) $value);
                $sets[] = "$field = '$escaped'";
            }
        }

        if (!$sets) {
            return jsonResponse($response, [
                'error' => 'No allowed fields to update',
                'debug_received_body' => $data
            ], 400);
        }

        $sql = "UPDATE persons SET " . implode(', ', $sets) . " WHERE id = $id";
        $pdo->exec($sql);

        $person = $pdo->query("SELECT * FROM persons WHERE id = $id")->fetch();

        return jsonResponse($response, [
            'message' => 'BMI record updated.',
            'person' => $person,
            'debug_received_body' => $data,
            'debug_sql' => $sql
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

$app->delete('/api/persons/{id}', function (Request $request, Response $response, array $args) {
    try {
        $pdo = getPDO();
        $id = $args['id'];

        // INSECURE: No auth, no ownership check, no role check.
        $sql = "DELETE FROM persons WHERE id = $id";
        $pdo->exec($sql);

        return jsonResponse($response, [
            'message' => 'BMI record deleted without role or ownership check.',
            'debug_sql' => $sql
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

// ----------------------------------------------------------
// Staff routes
// ----------------------------------------------------------
$app->get('/api/staff/persons', function (Request $request, Response $response) {
    try {
        $fakeUser = getFakeUserFromToken($request);

        if (!$fakeUser) {
            return jsonResponse($response, ['error' => 'Authentication required'], 401);
        }

        if (!in_array($fakeUser['role'] ?? '', ['staff', 'admin'], true)) {
            return jsonResponse($response, ['error' => 'Forbidden: staff role required'], 403);
        }

        $pdo = getPDO();

        $sql = "SELECT persons.*, users.email AS owner_email, users.role AS owner_role
                FROM persons
                JOIN users ON persons.user_id = users.id
                ORDER BY persons.id DESC";

        $persons = $pdo->query($sql)->fetchAll();

        return jsonResponse($response, [
            'message' => 'All BMI records returned without staff role check.',
            'persons' => $persons,
            'debug_sql' => $sql
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

$app->get('/api/staff/persons/{id}', function (Request $request, Response $response, array $args) {
    try {
        $pdo = getPDO();
        $id = $args['id'];

        // INSECURE - Review whether this route should allow all users
        $sql = "SELECT persons.*, users.email AS owner_email, users.role AS owner_role
                FROM persons
                JOIN users ON persons.user_id = users.id
                WHERE persons.id = $id";

        $person = $pdo->query($sql)->fetch();

        if (!$person) {
            return jsonResponse($response, ['error' => 'Record not found'], 404);
        }

        return jsonResponse($response, [
            'message' => 'Staff record returned without role check.',
            'person' => $person,
            'debug_sql' => $sql
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

// ----------------------------------------------------------
// Admin routes
// ----------------------------------------------------------
$app->get('/api/admin/users', function (Request $request, Response $response) {
    try {
        $fakeUser = getFakeUserFromToken($request);

        if (!$fakeUser) {
            return jsonResponse($response, ['error' => 'Authentication required'], 401);
        }

        if (($fakeUser['role'] ?? '') !== 'admin') {
            return jsonResponse($response, ['error' => 'Forbidden: admin role required'], 403);
        }

        $pdo = getPDO();

        // INSECURE: No admin role check.
        $sql = "SELECT id, name, email, role, created_at FROM users ORDER BY id ASC";
        $users = $pdo->query($sql)->fetchAll();

        return jsonResponse($response, [
            'message' => 'All users returned without admin role check.',
            'users' => $users,
            'debug_sql' => $sql
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

$app->put('/api/admin/users/{id}/role', function (Request $request, Response $response, array $args) {
    try {
        $pdo = getPDO();
        $id = $args['id'];
        $data = getRequestData($request);
        $role = $data['role'] ?? 'user';

        // INSECURE: No admin role check. Anyone can change any user role.
        $sql = "UPDATE users SET role = '$role' WHERE id = $id";
        $pdo->exec($sql);

        $stmt = $pdo->prepare("SELECT id, name, email, role, created_at FROM users WHERE id = :id");
        $stmt->execute([':id' => $id]);
        $user = $stmt->fetch();

        return jsonResponse($response, [
            'message' => 'User role changed without admin verification.',
            'user' => $user,
            'debug_received_body' => $data,
            'debug_sql' => $sql
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

$app->delete('/api/admin/persons/{id}', function (Request $request, Response $response, array $args) {
    try {
        $pdo = getPDO();
        $id = $args['id'];

        // INSECURE: No admin role check.
        $sql = "DELETE FROM persons WHERE id = $id";
        $pdo->exec($sql);

        return jsonResponse($response, [
            'message' => 'Admin delete executed without admin role verification.',
            'debug_sql' => $sql
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

// Preflight catch-all
$app->options('/{routes:.+}', function (Request $request, Response $response) {
    return $response;
});

$app->run();
