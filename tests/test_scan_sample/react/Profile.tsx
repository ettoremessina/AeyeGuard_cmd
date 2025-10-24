import React from 'react';

interface User {
    name: string;
    bio: string;
}

// XSS vulnerability with dangerouslySetInnerHTML
export function UserProfile({ user }: { user: User }) {
    return (
        <div>
            <h1>{user.name}</h1>
            <div dangerouslySetInnerHTML={{ __html: user.bio }} />
        </div>
    );
}

// Hardcoded API key
const API_KEY = "sk-1234567890abcdef";

export function fetchData() {
    fetch('/api/data', {
        headers: { 'Authorization': API_KEY }
    });
}
