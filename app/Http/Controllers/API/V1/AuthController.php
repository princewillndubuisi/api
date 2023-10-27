<?php

namespace App\Http\Controllers\API\V1;

use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    public function register(Request $request) {
        $validated = Validator::make( $request->all(), [
            'email' => 'required|email|unique:users,email',
            'password' => 'required|min:6',
            'username' => 'required|min:4|unique:users,username',
            'name' =>'required|min:4|max:30',
        ]);

        if ($validated -> fails()) {
            return $validated->errors();
        }

        $user = User::create([
            'email'=> $request->email,
            'name'=> $request->name,
            'username'=> $request->username,
            'password'=> bcrypt($request->password),
        ]);

        return response()->json([
            'status'=> 'success',
            'user'=> $user,
            'message'=>'User Created Successful'
        ]);
    }

    public function login(Request $request) {
        $validated = Validator::make( $request->all(), [
            'email' => 'required|email',
            'password' => 'required|min:6',
        ]);

        if ($validated -> fails()) {
            return $validated->errors();
        }

        $user = User::where('email', $request->email)->first();

        if(! $user || ! Hash::check($request->password, $user->password)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.']
            ]);
        }

        $token = $user->createToken('auth-token')->plainTextToken;
        return response()->json([
            'token'=> $token,
            'user'=> $user,
        ]);
    }

    public function show(Request $request)
    {

        $user = Auth::user();

        // Check if the user is authenticated
        if ($user) {
            return response()->json([
                'user' => $user,
            ]);
        } else {
            // If not authenticated, return an error response
            return response()->json([
                'error' => 'Unauthorized',
            ], 401);
        }
    }
}
