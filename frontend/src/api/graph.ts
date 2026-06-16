const BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');

export async function fetchGraphData() {
  const response = await fetch(`${BASE_URL}/graph/`);
  if (!response.ok) {
    throw new Error('Failed to fetch graph data');
  }
  return response.json();
}
