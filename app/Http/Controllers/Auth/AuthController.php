<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    public function Register(Request $req)
    {
        $fields=$req->validate([
            "name"=>"required | string",
            "email"=>"required|string|email|unique:users,email",
            "password"=>"required|min:6"
        ]);
        $user=User::create([
            "name"=>$fields['name'],
            "email"=>$fields['email'],
            "password"=>bcrypt($fields['password']),
        ]);
        $token=$user->createToken('myapptoken')->plainTextToken;
         return response()->json(['user'=>$user,"token"=>$token], 201);
    }
    public function login(Request $req)
    {
        $req->validate([
            "email"=>"required|email",
            "password"=>"required"
        ]);
        $user = User::where('email', $req->email)->first();

        if (! $user || ! Hash::check($req->password, $user->password)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }
    
        $token=$user->createToken('myapptoken')->plainTextToken;
         return response()->json(['user'=>$user,"token"=>$token], 201);
    }
    public function logout()
    {
        auth()->user()->tokens()->delete();
        return response()->json(['Logged out'],201);
    }
}
