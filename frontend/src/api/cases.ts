const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

export async function fetchCases() {
  const response = await fetch(`${BASE_URL}/cases/`);
  if (!response.ok) {
    throw new Error('Failed to fetch cases');
  }
  return response.json();
}
