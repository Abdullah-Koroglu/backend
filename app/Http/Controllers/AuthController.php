<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $firstName = $request->firstName;
        $lastName = $request->lastName;
        $email = $request->email;
        $password = $request->password;

        // Check if field is empty
        if (empty($firstName) or empty($lastName) or empty($email) or empty($password)) {
            return response()->json(['status' => 'error', 'message' => 'You must fill all the fields'], 401);
        }

        // Check if email is valid
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return response()->json(['status' => 'error', 'message' => 'You must enter a valid email'], 401);
        }

        // Check if password is greater than 5 character
        if (strlen($password) < 6) {
            return response()->json(['status' => 'error', 'message' => 'Password should be min 6 character'], 401);
        }

        // Check if user already exist
        if (User::where('email', '=', $email)->exists()) {
            return response()->json([ 'status' => 'error', 'message' => 'User already exists with this email'], 401);
        }

        // Create new user
        try {
            $user = new User();
            $user->firstName = $request->firstName;
            $user->lastName = $request->lastName;
            $user->email = $request->email;
            $user->role = $request->role ?? 'Editor';
            $user->color = $request->color ?? 0;
            $user->password = app('hash')->make($request->password);

            if ($user->save()) {
                return $this->login($request);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => 'error', 'message' => $e->getMessage()]);
        }
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }
    
    public function index()
    {
        $users = User::all();

        return $users;
    }

    public function login(Request $request)
    {
        $email = $request->email;
        $password = $request->password;

        // Check if field is empty
        if (empty($email) or empty($password)) {
            return response()->json(['status' => 'error', 'message' => 'You must fill all the fields']);
        }

        $credentials = request(['email', 'password']);

        if (!$token = auth()->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $user = User::where('email',$email)->first();

        $returnJson =  response()->json([
            'jwtToken' => $token,
            'firstName' => $user->firstName,
            'lastName' => $user->lastName,
            'email' => $user->email,
            'id' => $user->id,
            'color' => $user->color,
            'role' => $user->role,
            'user' => $user,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);

        return $returnJson;
    }
    
    public function refreshUserInfos(Request $request)
    {

        $token = $request->token;

        $returnJson = null;
        if ($token) {
            $tokenParts = explode(".", $token);  
            $tokenHeader = base64_decode($tokenParts[0]);
            $tokenPayload = base64_decode($tokenParts[1]);
            $jwtHeader = json_decode($tokenHeader);
            $jwtPayload = json_decode($tokenPayload);
            $id = $jwtPayload->sub;
            
            $user = User::find($id);

            $returnJson =  response()->json([
                'jwtToken' => $token,
                'firstName' => $user->firstName,
                'lastName' => $user->lastName,
                'email' => $user->email,
                'id' => $user->id,
                'color' => $user->color,
                'role' => $user->role,
                'user' => $user,
                'token_type' => 'bearer',
                'expires_in' => auth()->factory()->getTTL() * 60
            ]);
            return $returnJson;
        }
        return response()->json(['status' => 'error', 'message' => 'You need to send Token']);

    }
    
    public function updateUser(Request $request)
    {
        
        $token = $request->bearerToken();
        
        $tokenParts = explode(".", $token);  
        $tokenHeader = base64_decode($tokenParts[0]);
        $tokenPayload = base64_decode($tokenParts[1]);
        $jwtHeader = json_decode($tokenHeader);
        $jwtPayload = json_decode($tokenPayload);
        $id = $jwtPayload->sub;
        
        $user = User::find($id);
        if (User::where('email', '=', $request->email)->exists() && $user->email != $request->email) {
            return response()->json([ 'status' => 'error', 'message' => 'User exists with this email'], 405);
        }
        
        if ($request->firstName) {
            $user->firstName = $request->firstName;
        }
        if ($request->lastName) {
            $user->lastName = $request->lastName;
        }
        if ($request->email) {
            $user->email = $request->email;
        }
        if ($request->color) {
            $user->color = $request->color;
        }
        if ($request->password) {
            $user->password = app('hash')->make($request->password);
        }

        $user->save();
    
        // return view('edit-list')->with('page', $page);
        return $user;

    }

    /**
     * Get the token array structure.
     *
     * @param string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'jwtToken' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }
}
