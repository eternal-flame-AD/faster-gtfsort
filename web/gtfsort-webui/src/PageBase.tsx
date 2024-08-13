import { ReactNode, useState } from 'react'
import './App.css'
import { AppBar, IconButton, Toolbar } from '@mui/material'
import Typography from '@mui/material/Typography'
import { Box, Container } from '@mui/system'
import MenuIcon from '@mui/icons-material/Menu'
import { useMatches, useNavigate } from 'react-router-dom'

interface PersistentPage {
    path: string;
    element: ReactNode;
};

function routerMatch(matches: { pathname: string }[], path: string) {
    for (let i = 0; i < matches.length; i++) {
        if (matches[i].pathname === path) {
            return true;
        }
    }
    return false;
}


function PageBase({ children, persistentPages }: { children?: ReactNode, persistentPages: PersistentPage[] }) {
    const navigate = useNavigate();
    const matches = useMatches();

    const [openMenu, setOpenMenu] = useState(false);

    const handleMenuToggle = () => {
        setOpenMenu(!openMenu);
    };

    return (
        <Box sx={{ display: "flex" }}>

            <AppBar
                position="fixed"
                sx={{
                    width: { md: `100%` },
                    ml: { md: `0` },
                }}
            >
                <Container maxWidth="lg">
                    <Toolbar disableGutters>
                        <IconButton edge="start" color="inherit" aria-label="menu"
                            onClick={handleMenuToggle}
                            sx={{ mr: 2, display: { md: 'none' } }}
                        >
                            <MenuIcon />
                        </IconButton>
                        <Typography variant="h6" component="a"
                            onClick={() => { navigate("/") }}
                            sx={{ color: 'inherit', textDecoration: 'none', display: { md: 'flex' } }} >
                            GTFsort
                        </Typography>
                    </Toolbar>
                </Container>
            </AppBar >

            {
                (children ?
                    <Box
                        sx={{ width: "100%", display: "block", marginTop: "4em", padding: "1em" }}>
                        {children}
                    </Box> : null)
            }

            {
                persistentPages.map((page) => {
                    return (
                        <Box key={page.path} sx={{
                            width: "100%", display: routerMatch(matches, page.path)
                                ? "block" : "none"
                            , marginTop: "4em", padding: "1em"
                        }}>
                            {page.element}
                        </Box>
                    )
                })
            }
        </Box >
    )
}

export default PageBase