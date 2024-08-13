import './App.css'
import { createHashRouter, RouterProvider } from 'react-router-dom'
import PageBase from './PageBase'
import ProcessPage from './pages/ProcessPage'

const persistent_pagess = [
  {
    path: "/",
    element: <ProcessPage />,
  }
];

function App() {

  const router = createHashRouter([
    {
      path: '/',
      element: <PageBase persistentPages={persistent_pagess}></PageBase>
    }
  ])

  return (
    <RouterProvider router={router} />
  )
}

export default App
