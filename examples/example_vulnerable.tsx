import React, { useState, useEffect } from 'react';

interface User {
  id: number;
  name: string;
  bio: string;
}

// CRITICAL: XSS vulnerability - dangerouslySetInnerHTML with user input
function UserProfile({ user }: { user: User }) {
  return (
    <div className="profile">
      <h2>{user.name}</h2>
      <div dangerouslySetInnerHTML={{ __html: user.bio }} />
    </div>
  );
}

// HIGH: Sensitive data in localStorage
function AuthManager() {
  const login = (token: string) => {
    localStorage.setItem('authToken', token);
    localStorage.setItem('userPassword', 'secret123');
  };

  return <button onClick={() => login('abc123')}>Login</button>;
}

// MEDIUM: Missing useEffect dependencies
function DataFetcher({ userId }: { userId: number }) {
  const [data, setData] = useState(null);

  useEffect(() => {
    fetch(`/api/user/${userId}`)
      .then(res => res.json())
      .then(setData);
  }, []); // Missing userId dependency

  return <div>{JSON.stringify(data)}</div>;
}

// HIGH: Hardcoded API key
const API_KEY = "sk-1234567890abcdefghijklmnop";

function ApiClient() {
  const fetchData = () => {
    fetch('http://api.example.com/data', {
      headers: { 'X-API-Key': API_KEY }
    });
  };

  return <button onClick={fetchData}>Fetch</button>;
}

// CRITICAL: eval usage
function DynamicExecutor({ code }: { code: string }) {
  const execute = () => {
    eval(code);
  };

  return <button onClick={execute}>Execute</button>;
}

// MEDIUM: Type assertion to any
function UnsafeTypeAssertion(props: any) {
  const user = props.user as any;
  return <div>{user.data.secret}</div>;
}

// LOW: Console.log in production
function DebugComponent({ sensitiveData }: { sensitiveData: any }) {
  console.log('User data:', sensitiveData);
  console.error('Credentials:', sensitiveData.password);

  return <div>Check console</div>;
}

// HIGH: Open redirect
function RedirectHandler({ redirectUrl }: { redirectUrl: string }) {
  const handleRedirect = () => {
    window.location.href = redirectUrl; // User-controlled redirect
  };

  return <button onClick={handleRedirect}>Redirect</button>;
}

// HIGH: Direct DOM manipulation
function UnsafeDOMManipulation({ html }: { html: string }) {
  const ref = React.useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (ref.current) {
      ref.current.innerHTML = html; // Bypasses React's XSS protection
    }
  }, [html]);

  return <div ref={ref} />;
}

// MEDIUM: Unvalidated props spreading
function UnsafeComponent({ ...unknownProps }: any) {
  return <div {...unknownProps}>Content</div>;
}

export {
  UserProfile,
  AuthManager,
  DataFetcher,
  ApiClient,
  DynamicExecutor,
  UnsafeTypeAssertion,
  DebugComponent,
  RedirectHandler,
  UnsafeDOMManipulation,
  UnsafeComponent
};
